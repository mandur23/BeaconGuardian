import threading
import time
import logging
import ipaddress
from datetime import datetime

# scapy 경고 억제 후 임포트
import logging as _logging
_logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)

try:
    import os as _os
    _os.environ.setdefault("SCAPY_NO_BUNDLED_NPCAP", "1")  # 번들 npcap 자동설치 방지
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class NetworkMonitor(threading.Thread):
    def __init__(self, callback, interval=10, interface=None, agent_name="BeaconGuardian"):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.agent_name = agent_name
        # (src_ip, dst_ip, sport, dport, proto) -> {bytes, packets, first_seen, last_seen}
        self.traffic_aggregator = {}
        self._max_aggregator_keys = 50000
        # interval마다 전송할 레코드 수 상한 (초과분은 요약 1건으로 축약)
        self._max_send_per_interval = 300
        self._prev_io = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('NetworkMonitor')
        self.stop_event = threading.Event()
        self.daemon = True

        if not interface or str(interface).lower() in ("none", "null", "auto"):
            self.interface = self._detect_default_interface()
        else:
            self.interface = interface

        if _SCAPY_AVAILABLE:
            self.logger.info("네트워크 모니터: scapy(pcap) 모드로 동작합니다.")
        elif _PSUTIL_AVAILABLE:
            self.logger.warning(
                "Npcap/WinPcap 미설치 — psutil 폴백 모드로 동작합니다. "
                "정밀한 패킷 캡처를 원하면 https://npcap.com 에서 Npcap을 설치하세요."
            )
        else:
            self.logger.error("scapy와 psutil 모두 사용 불가 — 네트워크 모니터링이 비활성화됩니다.")

    def _detect_default_interface(self):
        """interface 미지정 시 활성 NIC 또는 scapy 기본 인터페이스를 선택합니다."""
        if not _PSUTIL_AVAILABLE:
            if _SCAPY_AVAILABLE:
                try:
                    from scapy.config import conf
                    if conf.iface:
                        return str(conf.iface)
                except Exception:
                    pass
            return None
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()

            for nic, stat in stats.items():
                if stat.isup and nic not in ("lo", "localhost", "loopback"):
                    if nic in addrs:
                        for addr in addrs[nic]:
                            if addr.family == 2:  # AF_INET
                                self.logger.info(
                                    "Dynamically detected active interface: %s", nic
                                )
                                return nic

            if _SCAPY_AVAILABLE:
                from scapy.config import conf

                if conf.iface:
                    self.logger.info(
                        "Fallback to Scapy default interface: %s", conf.iface
                    )
                    return str(conf.iface)
        except Exception as e:
            self.logger.debug("Failed to dynamically detect interface: %s", e)
        return None

    def _packet_callback(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = "OTHER"
            sport = 0
            dport = 0

            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"

            key = (src_ip, dst_ip, sport, dport, proto)

            with self.lock:
                now = time.time()
                if key not in self.traffic_aggregator:
                    if len(self.traffic_aggregator) >= self._max_aggregator_keys:
                        self.logger.warning(
                            "traffic_aggregator reached %d keys, forcing early flush",
                            self._max_aggregator_keys,
                        )
                        self.traffic_aggregator.clear()
                    self.traffic_aggregator[key] = {
                        "bytes": 0,
                        "packets": 0,
                        "first_seen": now
                    }

                stats = self.traffic_aggregator[key]
                stats["bytes"] += len(packet)
                stats["packets"] += 1
                stats["last_seen"] = now

    def run(self):
        self.logger.info(f"Starting network monitor thread on interface: {self.interface}")

        if _SCAPY_AVAILABLE:
            sniffer = threading.Thread(target=self._run_sniff, daemon=True)
            sniffer.start()
        elif _PSUTIL_AVAILABLE:
            self._init_psutil_baseline()

        while not self.stop_event.is_set():
            time.sleep(self.interval)
            try:
                if _SCAPY_AVAILABLE:
                    traffic_list = self.get_and_clear_traffic()
                elif _PSUTIL_AVAILABLE:
                    traffic_list = self._poll_psutil()
                else:
                    traffic_list = []

                traffic_list = self._prepare_send_batch(traffic_list)
                for traffic in traffic_list:
                    try:
                        self.callback(traffic)
                    except Exception as cb_err:
                        self.logger.error("Traffic callback failed: %s", cb_err)
            except Exception as e:
                self.logger.error(f"Error in network monitor: {e}")

    def _prepare_send_batch(self, traffic_list):
        """과도한 전송 건수를 제한하고 초과분을 1건으로 요약."""
        if len(traffic_list) <= self._max_send_per_interval:
            return traffic_list

        ranked = sorted(
            traffic_list,
            key=lambda t: int(t.get("bytesTransferred", 0) or 0),
            reverse=True,
        )
        keep_n = max(1, self._max_send_per_interval - 1)
        keep = ranked[:keep_n]
        overflow = ranked[keep_n:]
        dropped_count = len(overflow)
        dropped_bytes = sum(int(t.get("bytesTransferred", 0) or 0) for t in overflow)
        dropped_packets = sum(int(t.get("packetsTransferred", 0) or 0) for t in overflow)

        keep.append({
            "sourceIp": "0.0.0.0",
            "destinationIp": "0.0.0.0",
            "sourcePort": 0,
            "destinationPort": 0,
            "protocol": "AGG_OVERFLOW",
            "bytesTransferred": dropped_bytes,
            "packetsTransferred": dropped_packets,
            "duration": self.interval,
            "isInternal": False,
        })

        self.logger.warning(
            "Network batch throttled: %d -> %d records (overflow %d summarized)",
            len(traffic_list),
            len(keep),
            dropped_count,
        )
        return keep

    def _run_sniff(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: self.stop_event.is_set(),
            )
        except Exception as e:
            self.logger.error(f"Error during sniffing: {e}. (관리자 권한으로 실행했는지 확인하세요)")

    def _init_psutil_baseline(self):
        try:
            self._prev_io = psutil.net_io_counters(pernic=True)
        except Exception:
            self._prev_io = {}

    def _poll_psutil(self):
        results = []
        try:
            connections = psutil.net_connections(kind="inet")
            curr_io = psutil.net_io_counters(pernic=True)

            total_sent = total_recv = 0
            for nic, stats in curr_io.items():
                prev = self._prev_io.get(nic)
                if prev:
                    total_sent += max(0, stats.bytes_sent - prev.bytes_sent)
                    total_recv += max(0, stats.bytes_recv - prev.bytes_recv)
            self._prev_io = curr_io

            seen = set()
            for conn in connections:
                if conn.status != "ESTABLISHED":
                    continue
                if not conn.laddr or not conn.raddr:
                    continue

                key = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port)
                if key in seen:
                    continue
                seen.add(key)

                proto = "TCP" if conn.type == 1 else "UDP"
                results.append({
                    "sourceIp":         conn.laddr.ip,
                    "destinationIp":    conn.raddr.ip,
                    "sourcePort":       conn.laddr.port,
                    "destinationPort":  conn.raddr.port,
                    "protocol":         proto,
                    "bytesTransferred": (total_sent + total_recv) // max(1, len(seen)),
                    "packetsTransferred": 1,
                    "duration":         self.interval,
                    "isInternal":       self.is_internal_ip(conn.laddr.ip) and self.is_internal_ip(conn.raddr.ip),
                })
        except Exception as e:
            self.logger.error(f"psutil 네트워크 폴링 오류: {e}")
        return results

    def is_internal_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def get_and_clear_traffic(self):
        with self.lock:
            snapshot = self.traffic_aggregator
            self.traffic_aggregator = {}

        conn_map = {}
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.laddr and c.raddr:
                    key = (c.laddr.ip, c.raddr.ip, c.laddr.port, c.raddr.port)
                    conn_map[key] = c.pid
        except Exception:
            pass

        aggregated_data = []
        for key, stats in snapshot.items():
            src_ip, dst_ip, sport, dport, proto = key
            duration = max(1, int(stats["last_seen"] - stats["first_seen"]))

            pid = conn_map.get((src_ip, dst_ip, sport, dport))
            process_name = "Unknown"
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except Exception:
                    pass

            import json
            raw_meta = {
                "process_name": process_name,
                "pid": pid,
                "first_seen": datetime.fromtimestamp(stats["first_seen"]).isoformat(),
                "last_seen": datetime.fromtimestamp(stats["last_seen"]).isoformat(),
                "system_description": f"{process_name} (PID: {pid}) 프로세스가 {proto} 통신을 생성함."
            }

            traffic_entry = {
                "sourceIp": src_ip,
                "destinationIp": dst_ip,
                "sourcePort": sport,
                "destinationPort": dport,
                "protocol": proto,
                "bytesTransferred": stats["bytes"],
                "packetsTransferred": stats["packets"],
                "duration": duration,
                "rawData": json.dumps(raw_meta),
                "agentName": getattr(self, 'agent_name', 'BeaconGuardian'),
                "isInternal": self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip)
            }
            aggregated_data.append(traffic_entry)

        return aggregated_data

    def stop(self):
        self.stop_event.set()
