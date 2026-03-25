import threading
import time
import logging
import ipaddress

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
    def __init__(self, callback, interval=10, interface=None):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.interface = interface
        # (src_ip, dst_ip, sport, dport, proto) -> {bytes, packets, first_seen, last_seen}
        self.traffic_aggregator = {}
        self._prev_io = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger('NetworkMonitor')
        self.stop_event = threading.Event()
        self.daemon = True

        if _SCAPY_AVAILABLE:
            self.logger.info("네트워크 모니터: scapy(pcap) 모드로 동작합니다.")
        elif _PSUTIL_AVAILABLE:
            self.logger.warning(
                "Npcap/WinPcap 미설치 — psutil 폴백 모드로 동작합니다. "
                "정밀한 패킷 캡처를 원하면 https://npcap.com 에서 Npcap을 설치하세요."
            )
        else:
            self.logger.error("scapy와 psutil 모두 사용 불가 — 네트워크 모니터링이 비활성화됩니다.")

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

                for traffic in traffic_list:
                    self.callback(traffic)
            except Exception as e:
                self.logger.error(f"Error in network monitor: {e}")

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

    # ── psutil 폴백: 연결 목록 + I/O 카운터 ──────────────────────────────

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
        
        aggregated_data = []
        for key, stats in snapshot.items():
            src_ip, dst_ip, sport, dport, proto = key
            duration = max(1, int(stats["last_seen"] - stats["first_seen"]))
            
            traffic_entry = {
                "sourceIp": src_ip,
                "destinationIp": dst_ip,
                "sourcePort": sport,
                "destinationPort": dport,
                "protocol": proto,
                "bytesTransferred": stats["bytes"],
                "packetsTransferred": stats["packets"],
                "duration": duration,
                "isInternal": self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip)
            }
            aggregated_data.append(traffic_entry)
            
        return aggregated_data

    def stop(self):
        self.stop_event.set()
