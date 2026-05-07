import yaml
import time
import logging
import logging.handlers
import signal
import sys
import argparse
import os
import platform
import json
import random
import subprocess
import urllib3
from datetime import datetime

# [NEW] SSL 경고(InsecureRequestWarning) 비활성화
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 프로젝트 루트: 번들(frozen) 시 EXE 위치, 일반 실행 시 src/의 부모 폴더
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# src/ 폴더를 sys.path에 추가 (동일 폴더 모듈 임포트)
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from beacon.beacon_client import BeaconClient
from core.credential_store import encrypt_password, is_encrypted
from monitors.usb_monitor import USBMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.file_watcher import FileWatcher
from monitors.browser_monitor import BrowserMonitor
from monitors.input_biometric_monitor import InputBiometricMonitor
from monitors.suricata_monitor import SuricataMonitor
from monitors.auth_monitor import AuthMonitor
from core.active_response import ActiveResponseManager
from firewall.local_block_controller import LocalBlockController

class SecurityAgent:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.path.join(ROOT_DIR, 'config.yaml')
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.logger = logging.getLogger('SecurityAgent')

        # Initialize Beacon Client
        bc_conf = self.config['beacon']
        ag_conf = self.config.get('agent', {})
        ui_conf = self.config.get('ui', {})
        import socket
        base_name = ag_conf.get('agent_name', 'BeaconGuardian')
        # 도커 scale 환경에서 이름이 중복되지 않도록 호스트네임(컨테이너 ID)을 접미사로 붙임
        unique_name = f"{base_name}-{socket.gethostname()}" if "DOCKER" in base_name.upper() else base_name

        self.client = BeaconClient(
            bc_conf['server_url'],
            bc_conf['username'],
            bc_conf['password'],
            agent_name=unique_name,
            agent_version=ag_conf.get('agent_version', '1.0.0'),
            heartbeat_interval_seconds=ag_conf.get('heartbeat_interval_seconds', 10),
            tls=bc_conf.get('tls', {}),
            ip_selection=bc_conf.get('ip_selection', 'outbound'),
            jwt_refresh_before_exp_seconds=bc_conf.get('jwt_refresh_before_exp_seconds', 90),
            admin_usernames=ui_conf.get('admin_usernames'),
        )
        
        # 모니터링 관련 설정 로드
        mon_conf = self.config.get('monitoring', {})
        collectors = mon_conf.get('collectors', {})
        path_conf = self.config.get('paths', {})
        
        # [NEW] 실시간 차단 컨트롤러 및 능동 대응 매니저 초기화
        self.block_controller = LocalBlockController()
        self.active_response = ActiveResponseManager(self.config, self.block_controller)

        # 모니터링 엔진 모드 선택 (builtin vs wazuh)
        engine_mode = mon_conf.get('engine', 'builtin').lower()

        # Wazuh 하이브리드 모니터 [NEW]
        self.wazuh_mon = None
        if engine_mode == 'wazuh':
            from monitors.wazuh_monitor import WazuhMonitor
            wz_conf = self.config.get('wazuh', {})
            self.logger.info(f"보안 엔진: WAZUH 하이브리드 모드 활성화 (컨테이너: {wz_conf.get('container_name')})")
            self.wazuh_mon = WazuhMonitor(
                callback=self._handle_security_event, # [MOD] 중앙 처리기로 변경
                wazuh_container=wz_conf.get('container_name', 'single-node-wazuh.manager-1'),
                min_level=wz_conf.get('min_level', 5)
            )

        self.usb_mon = None
        if collectors.get('usb', True):
            self.usb_mon = USBMonitor(
                callback=self._handle_security_event, # [MOD] 중앙 처리기로 변경
                interval=mon_conf.get('usb_check_interval', 5)
            )

        self.net_mon = None
        if collectors.get('network', True):
            self.net_mon = NetworkMonitor(
                callback=self.client.send_traffic,
                interval=mon_conf.get('network_check_interval', 10),
                agent_name=unique_name # [NEW] 에이전트 이름 전달
            )

        self.proc_mon = None
        if collectors.get('process', True) and engine_mode != 'wazuh':
            self.proc_mon = ProcessMonitor(
                callback=self.client.send_event,
                interval=mon_conf.get('process_check_interval', 5)
            )

        self.file_watcher = None
        if collectors.get('filesystem', True) and engine_mode != 'wazuh':
            self.file_watcher = FileWatcher(
                callback=self._handle_security_event, # [MOD] 중앙 처리기로 변경하여 자동 차단 기능 연동
                directories=path_conf.get('watch_dirs', []),
                ignore_dirs=path_conf.get('ignore_dirs', []),
                ignore_extensions=path_conf.get('ignore_extensions', []),
                critical_dirs=path_conf.get('critical_dirs', []),
                critical_extensions=path_conf.get('critical_extensions', [])
            )
            
        # USB DLP를 위한 file_watcher 강제 활성화 (Wazuh 모드라도 USB 동적 감시는 유지)
        if engine_mode == 'wazuh' and collectors.get('usb', True):
            self.file_watcher = FileWatcher(
                callback=self._handle_security_event, 
                directories=[],
                ignore_dirs=path_conf.get('ignore_dirs', []),
                ignore_extensions=path_conf.get('ignore_extensions', []),
                critical_dirs=path_conf.get('critical_dirs', []),
                critical_extensions=path_conf.get('critical_extensions', [])
            )

        self.browser_mon = None
        if collectors.get('browser_history', True):
            self.browser_mon = BrowserMonitor(
                callback=self.client.send_event,
                interval=mon_conf.get('browser_check_interval', 30)
            )

        # 입력 생체 데이터(키보드/마우스): Spring 전송 없이 로컬 파일에만 저장
        self.input_bio_mon = None
        if collectors.get('input_biometric', True):
            bio_path = path_conf.get('biometric_log_file', 'logs/biometric_input.jsonl')
            if not os.path.isabs(bio_path):
                bio_path = os.path.join(ROOT_DIR, bio_path)
            self.input_bio_mon = InputBiometricMonitor(
                output_path=bio_path,
                callback=self.client.send_event,
                target_samples=mon_conf.get('biometric_target_samples', 2000),
                auto_block=mon_conf.get('biometric_auto_block', False)
            )

        self.suricata_mon = None
        suri_conf = self.config.get('suricata', {})
        if suri_conf.get('enabled', False):
            self.suricata_mon = SuricataMonitor(
                callback=self._handle_security_event, # [MOD] 중앙 처리기로 변경
                config=suri_conf
            )
        
        # [NEW] 빌트인 엔진용 Windows 인증 모니터 (로그인 시도 탐지)
        self.auth_mon = None
        if engine_mode != 'wazuh' and platform.system() == "Windows":
            self.logger.info("빌트인 엔진: Windows 인증 보안 모니터 활성화")
            self.auth_mon = AuthMonitor(
                callback=self._handle_security_event
            )

        self.firewall_sync = None
        self.firewall_cmds = None

        # [NEW] Heartbeat에 포함될 동적 메타데이터 공급자 등록
        self.client.heartbeat_metadata_provider = self._get_heartbeat_metadata
        fw_conf = self.config.get("firewall") or {}
        if fw_conf.get("enabled") and platform.system() == "Windows":
            from firewall.desired_state_sync import FirewallDesiredStateSync
            from firewall.command_receiver import FirewallCommandReceiver
            from firewall.local_state_store import LocalStateStore
            from firewall.wfas_applier import WindowsFirewallApplier

            state_rel = (fw_conf.get("state_file") or "").strip()
            if state_rel:
                state_path = (
                    state_rel if os.path.isabs(state_rel) else os.path.join(ROOT_DIR, state_rel)
                )
            else:
                pd = os.environ.get("ProgramData") or ROOT_DIR
                state_path = os.path.join(pd, "BeaconGuardian", "firewall_state.json")
            store = LocalStateStore(state_path)
            applier = WindowsFirewallApplier(
                rule_name_prefix=fw_conf.get("rule_name_prefix") or "BeaconGuardian/"
            )
            self.firewall_sync = FirewallDesiredStateSync(
                self.client,
                applier,
                store,
                interval_seconds=float(fw_conf.get("sync_interval_seconds", 120)),
                report_status=bool(fw_conf.get("report_status", True)),
            )
            self.firewall_cmds = FirewallCommandReceiver(
                self.client,
                applier,
                store,
                long_poll_timeout=float(fw_conf.get("long_poll_seconds", 75)),
                channel_b_enabled=bool(fw_conf.get("channel_b", True)),
                endpoint_missing_backoff=float(fw_conf.get("command_poll_backoff_seconds", 30)),
            )
        elif fw_conf.get("enabled"):
            self.logger.info("firewall.enabled 이지만 Windows가 아니어서 방화벽 모듈을 건너뜁니다.")

        self.running = True

    def _handle_security_event(self, event):
        """[CORE] 모든 모니터링 이벤트의 실시간 차단 여부를 판단하고 서버로 전송합니다."""
        try:
            # 1. 능동 대응 매니저에게 평가 요청
            action = self.active_response.evaluate_and_respond(event)
            
            if action:
                # 차단이 수행된 경우 이벤트 메타데이터에 기록 추가
                event['active_response'] = action
                if 'metadata' not in event: event['metadata'] = {}
                event['metadata']['blocked'] = True
                self.logger.warning(f"🛡️ [ActiveResponse] 위협 차단됨: {action}")

            # 2. 서버 표준 형식으로 이벤트 정규화 (Normalization)
            normalized_event = self._normalize_for_server(event)

            # 3. 서버 대시보드로 이벤트 전송
            self.client.send_event(normalized_event)
        except Exception as e:
            self.logger.error(f"보안 이벤트 처리 중 오류 발생: {e}")
            # 에러 발생 시에도 원본 전송 시도
            self.client.send_event(event)

    def _normalize_for_server(self, event):
        """가공되지 않은 보안 경보(Suricata, Wazuh 등)를 서버가 이해하는 SecurityEvent 형식으로 변환합니다."""
        norm = {
            "agentName": self.client.agent_name,
            "eventType": "GENERAL_EVENT",
            "severity": "INFO",
            "summary": "Security Event Detected",
            "description": "",
            "sourceIp": self.client.system_info.get("ipAddress", "127.0.0.1"),
            "protocol": "TCP",
            "port": 0,
            "metadata": event.get('metadata', event),
            "rawData": event
        }

        # [Suricata 매핑] - 모든 수리카타 이벤트(event_type 필드 존재) 처리
        if 'event_type' in event:
            norm["sourceIp"] = event.get('src_ip', norm["sourceIp"])
            norm["destinationIp"] = event.get('dest_ip', norm.get("destinationIp"))
            norm["protocol"] = event.get('proto', norm["protocol"])
            norm["port"] = event.get('dest_port', 0)
            
            e_type = event.get('event_type')
            if e_type == 'alert':
                alert = event.get('alert', {})
                norm["eventType"] = "IDS_ALERT"
                sev_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}
                norm["severity"] = sev_map.get(alert.get('severity'), "LOW")
                norm["summary"] = f"Network Attack: {alert.get('signature', 'Unknown')}"
                norm["description"] = f"Category: {alert.get('category')}, IP: {norm['sourceIp']} -> {norm['destinationIp']}"
            elif e_type == 'dns':
                dns = event.get('dns', {})
                queries = dns.get('queries', [{}])
                qname = queries[0].get('rrname', 'unknown')
                norm["eventType"] = "IDS_DNS"
                norm["summary"] = f"DNS Query: {qname}"
                norm["description"] = f"DNS {dns.get('type')} request for {qname}"
            elif e_type == 'http':
                http = event.get('http', {})
                norm["eventType"] = "IDS_HTTP"
                norm["summary"] = f"HTTP {http.get('http_method')}: {http.get('hostname')}{http.get('url')}"
                norm["description"] = f"User-Agent: {http.get('http_user_agent')}"
            else:
                norm["eventType"] = f"IDS_{e_type.upper()}"
                norm["summary"] = f"Suricata {e_type} Event"
                norm["description"] = f"Source: {norm['sourceIp']} -> {norm['destinationIp']}"

        # [Wazuh 매핑]
        elif event.get('eventType') == 'WAZUH_ALERT':
            meta = event.get('metadata', {})
            norm["eventType"] = "WAZUH_ALERT"
            lvl_val = meta.get('rule', {}).get('level') or meta.get('level', 0)
            lvl = int(lvl_val) if lvl_val else 0
            if lvl >= 12: norm["severity"] = "CRITICAL"
            elif lvl >= 10: norm["severity"] = "HIGH"
            elif lvl >= 5: norm["severity"] = "MEDIUM"
            else: norm["severity"] = "LOW"
            norm["summary"] = event.get('summary', 'Wazuh Host Alert')
            norm["description"] = event.get('description', '')

        # [기타 내장 이벤트]
        else:
            norm["eventType"] = event.get("eventType", "SYSTEM_EVENT")
            norm["severity"] = event.get("severity", "INFO")
            norm["summary"] = event.get("summary", "Internal Agent Event")
            norm["description"] = event.get("description", "")

        # [NEW] 로그온 실패 이벤트 상세 매핑
        if norm["eventType"] == "USER_LOGIN_FAILED":
            norm["severity"] = "HIGH"
            norm["summary"] = f"Unauthorized Access Attempt (User: {event.get('metadata', {}).get('user')})"

        return norm

    def run_test_scenario(self, scenario):
        """자가 진단 및 위협 탐지 테스트 시나리오 수행"""
        self.logger.info(f"== 테스트 시나리오 실행: {scenario} ==")
        
        if scenario == "ids-v": # IDS Virtual
            self._test_ids_virtual()
        elif scenario == "ids-r": # IDS Real
            self._test_ids_real()
        elif scenario == "file": # File Watcher
            self._test_file_watcher()
        elif scenario == "bio": # Biometric Virtual
            self._test_biometric_virtual()
        elif scenario == "ddos": # DDoS Simulation
            self._test_ddos_virtual()
        else:
            self.logger.error(f"알 수 없는 시나리오: {scenario}")

    def _test_ids_virtual(self):
        suri_conf = self.config.get('suricata', {})
        eve_log = suri_conf.get('eve_log_path', r"C:\Program Files\Suricata\log\eve.json")
        payload = {
            "timestamp": datetime.now().isoformat() + "+0900",
            "event_type": "alert",
            "src_ip": f"10.0.0.{random.randint(2,254)}",
            "dest_ip": "1.2.3.4",
            "proto": "TCP",
            "alert": {
                "signature": "POC_TEST: Virtual IDS Simulation via Agent CLI",
                "category": "Diagnostic Test",
                "severity": 1
            }
        }
        try:
            os.makedirs(os.path.dirname(eve_log), exist_ok=True)
            with open(eve_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
            print(f"[SUCCESS] 가상 IDS 경보를 {eve_log}에 주입했습니다.")
            
            # [MOD] 서버 대시보드로 직접 전송 대신 중앙 처리기 거치게 하여 차단 테스트 수행
            self._handle_security_event(payload)
            print("[INFO] 가상 IDS 이벤트가 서버 대시보드로 즉시 전송되었습니다.")
        except Exception as e:
            print(f"[ERROR] IDS 시뮬레이션 실패: {e}")

    def _test_ids_real(self):
        try:
            print("[INFO] testmyids.com 접속을 통해 실제 IDS 배치를 시뮬레이션합니다.")
            subprocess.run(["curl", "-s", "http://testmyids.com"], capture_output=True)
            print("[SUCCESS] 요청 완료. 수리카타 탐지 여부를 대시보드에서 확인하세요.")
        except Exception as e:
            print(f"[ERROR] 실기 IDS 테스트 실패 (curl 확인 필요): {e}")

    def _test_file_watcher(self):
        watch_dirs = self.config.get('paths', {}).get('watch_dirs', [])
        if not watch_dirs:
            print("[ERROR] 설정된 감시 경로가 없습니다.")
            return
        test_file = os.path.join(watch_dirs[0], "GUARD_CLI_TEST.txt")
        file_event = {
            "eventType": "FILE_CREATED",
            "severity": "MEDIUM",
            "summary": "CLI File Watcher Test",
            "description": f"테스트 파일 생성/삭제: {test_file}",
            "metadata": {"path": test_file, "test_mode": True},
        }
        try:
            with open(test_file, "w") as f: f.write("CLI Test")
            time.sleep(1)
            os.remove(test_file)
            print(f"[SUCCESS] {test_file} 생성 및 삭제 완료. 가디언 탐지를 확인하세요.")
            
            # [MOD] 중앙 처리기를 거치도록 수정 (능동 대응 테스트 가능)
            self._handle_security_event(file_event)
            print("[INFO] 파일 탐지 이벤트가 서버 대시보드로 전송되었습니다.")
        except Exception as e:
            print(f"[ERROR] 파일 테스트 실패: {e}")

    def _test_biometric_virtual(self):
        bio_log = self.config.get('paths', {}).get('biometric_log_file', 'logs/biometric_input.jsonl')
        if not os.path.isabs(bio_log):
            bio_log = os.path.join(ROOT_DIR, bio_log)
        payload = {
            "timestamp": time.time(),
            "event_type": "biometric_anomaly",
            "mse": 0.88,
            "anomaly_score": 0.92,
            "engine_mode": "GUARDING",
            "description": "POC: Simulated behavior mismatch via Agent CLI"
        }
        try:
            os.makedirs(os.path.dirname(bio_log), exist_ok=True)
            with open(bio_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
            print(f"[SUCCESS] 가상 이상치 데이터를 {bio_log}에 주입했습니다.")
            
            # [MOD] 중앙 처리기를 거치도록 수정
            self._handle_security_event(payload)
            print("[INFO] 생체 인증 이상 이벤트가 서버 대시보드로 전송되었습니다.")
        except Exception as e:
            print(f"[ERROR] Biometric 시뮬레이션 실패: {e}")

    def _test_ddos_virtual(self):
        """대량의 SYN Flood 공격을 시뮬레이션하여 자동 차단을 테스트합니다."""
        attacker_ip = f"182.16.1.{random.randint(100, 200)}"
        payload = {
            "timestamp": datetime.now().isoformat() + "+0900",
            "event_type": "alert",
            "src_ip": attacker_ip,
            "dest_ip": "192.168.0.10",
            "proto": "TCP",
            "alert": {
                "signature": "ET DOS Possible SYN Flood Detected (Simulated)",
                "category": "Attempted Denial of Service",
                "severity": 1
            }
        }
        print(f"[INFO] DDoS 시뮬레이션 시작: 공격자 IP={attacker_ip}")
        try:
            # 능동 대응 엔진 호출 (이 과정에서 방화벽 차단이 일어나야 함)
            self._handle_security_event(payload)
            print(f"[SUCCESS] DDoS 경보가 처리되었습니다. 방화벽에 {attacker_ip} 차단 규칙이 생성되었는지 확인하세요.")
        except Exception as e:
            print(f"[ERROR] DDoS 시뮬레이션 도중 오류 발생: {e}")

    def get_system_snapshot(self):
        """현재 시스템의 주요 수집 대상 상태를 스냅샷으로 찍어 반환합니다."""
        snapshot = {
            "usb": [],
            "processes": []
        }
        
        # USB 스냅샷
        try:
            from monitors.usb_monitor import USBMonitor
            temp_usb = USBMonitor(callback=None)
            snapshot["usb"] = temp_usb._get_all_usb_devices()
        except Exception as e:
            self.logger.error(f"Snapshot USB failed: {e}")

        # 프로세스 스냅샷
        try:
            import psutil
            snapshot["processes"] = {p.pid: p.info['name'] for p in psutil.process_iter(['pid', 'name'])}
        except Exception as e:
            self.logger.error(f"Snapshot Process failed: {e}")
            
        return snapshot

    def run_diff_test(self, before, scenario):
        """이전 스냅샷(before)과 현재 상태를 비교하여 변동 사항을 서버로 전송합니다."""
        after = self.get_system_snapshot()
        diff_report = []
        
        if scenario == "usb":
            before_drives = set(before.get("usb", {}).keys())
            after_drives = set(after.get("usb", {}).keys())
            
            added = after_drives - before_drives
            removed = before_drives - after_drives
            
            for d in added:
                info = after["usb"][d]
                event = {
                    "eventType": "USB_CONNECTED",
                    "severity": "MEDIUM",
                    "summary": f"비교 테스트: USB 연결 감지 ({info.get('name')})",
                    "description": f"스냅샷 비교를 통해 신규 USB 장치({info.get('category')})를 탐지했습니다.",
                    "metadata": info
                }
                # [ADD] 실시간 파일 감시 연동 (DLP)
                mountpoint = info.get("mountpoint")
                if mountpoint and self.file_watcher:
                    self.logger.info(f"USB 실시간 감시 시작: {mountpoint}")
                    self.file_watcher.add_watch_path(mountpoint)

                # [ADD] 내부 파일 목록 표시
                file_list = info.get("file_list", [])
                if file_list:
                    diff_report.append("    [내부 파일 목록]")
                    for f in file_list:
                        diff_report.append(f"      - {f}")
                else:
                    if info.get("category") in ["Storage", "Smartphone/Portable"]:
                        diff_report.append("    (파일 목록 없음 - 드라이브가 아직 마운트되지 않았거나 접근 권한이 없습니다)")
                
            for d in removed:
                info = before["usb"][d]
                event = {
                    "eventType": "USB_DISCONNECTED",
                    "severity": "LOW",
                    "summary": f"비교 테스트: USB 제거 감지 ({info.get('name')})",
                    "description": f"스냅샷 비교를 통해 USB 장치({info.get('category')})의 연결 해제를 탐지했습니다.",
                    "metadata": info
                }
                self.client.send_event(event)
                diff_report.append(f"[-] USB 제거됨: {info.get('name')} ({info.get('category')})")
                print(f"[INFO] USB 제거 이벤트({info.get('name')})가 서버로 전송되었습니다.")
        
        elif scenario == "process":
            before_pids = set(before.get("processes", {}).keys())
            after_pids = set(after.get("processes", {}).keys())
            
            added = after_pids - before_pids
            for pid in added:
                name = after["processes"].get(pid, "unknown")
                event = {
                    "eventType": "PROCESS_START",
                    "severity": "LOW",
                    "summary": f"비교 테스트: 새 프로세스 감지 ({name})",
                    "description": f"스냅샷 비교를 통해 신규 프로세스(PID: {pid})의 시작을 탐지했습니다.",
                    "metadata": {"pid": pid, "name": name}
                }
                self.client.send_event(event)
                diff_report.append(f"[+] 프로세스 시작: {name} (PID: {pid})")
                
        return diff_report

    def _load_config(self, path):
        if not os.path.exists(path):
            print(f"Error: Config file not found at {path}")
            sys.exit(1)
        with open(path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)

        # 평문 비밀번호가 있으면 암호화하여 config.yaml에 다시 저장
        bc = cfg.get('beacon', {})
        pwd = bc.get('password', '')
        if pwd and not is_encrypted(pwd):
            bc['password'] = encrypt_password(pwd)
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)

        return cfg

    def _setup_logging(self):
        log_conf = self.config.get('logging', {})
        level = getattr(logging, log_conf.get('level', 'INFO').upper())
        log_file = log_conf.get('file', 'logs/agent.log')
        max_bytes = log_conf.get('max_bytes', 10485760)
        backup_count = log_conf.get('backup_count', 5)

        # 상대 경로는 프로젝트 루트 기준으로 절대 경로 변환
        if not os.path.isabs(log_file):
            log_file = os.path.join(ROOT_DIR, log_file)
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        
        # Root logger setup
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        if root_logger.handlers:
            root_logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Stream handler (Console)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)

    def run(self):
        self.logger.info("Security Agent starting...")
        
        # Initial login
        if not self.client.login():
            self.logger.warning("Initial login failed. Will retry automatically.")

        # Start enabled monitor threads
        for mon in (self.usb_mon, self.net_mon, self.proc_mon,
                     self.file_watcher, self.browser_mon, self.input_bio_mon, self.suricata_mon, self.wazuh_mon, self.auth_mon):
            if mon is not None:
                mon.start()

        if self.firewall_cmds is not None:
            self.firewall_cmds.start()
        if self.firewall_sync is not None:
            self.firewall_sync.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.logger.info("Stopping agent gracefully...")
        self.running = False

        # Stop enabled threads
        for mon in (self.usb_mon, self.net_mon, self.proc_mon,
                     self.file_watcher, self.browser_mon, self.input_bio_mon, self.suricata_mon, self.wazuh_mon, self.auth_mon):
            if mon is not None:
                mon.stop()

        if self.firewall_sync is not None:
            self.firewall_sync.stop()
        if self.firewall_cmds is not None:
            self.firewall_cmds.stop()

        # 서버에 연결 해제 알림 후 민감 정보 정리
        self.client.disconnect()
        self.client.stop_heartbeat()
        self.client.clear_credentials()

        self.logger.info("Agent stopped.")
        sys.exit(0)

    def _get_heartbeat_metadata(self):
        """서버에 전송할 최신 에이전트 상태(생체 인증 등)를 수집합니다."""
        meta = {
            "platform": platform.platform(),
            "timestamp": datetime.now().isoformat()
        }

        # 생체 인증 모니터 정보 수집
        if self.input_bio_mon and self.input_bio_mon.engine:
            engine = self.input_bio_mon.engine
            meta["biometric"] = {
                "mode": engine.mode,
                "progress": round(engine.progress, 1),
                "sample_count": engine.sample_count,
                "target_samples": engine.target_samples,
                "thresholds": {
                    "lstm": round(engine.lstm_threshold, 6),
                    "if": round(engine.if_threshold, 4)
                }
            }

        # [NEW] 활성화된 모니터링 엔진 현황 수집
        meta["active_monitors"] = {
            "usb": self.usb_mon is not None,
            "network": self.net_mon is not None,
            "process": self.proc_mon is not None,
            "file": self.file_watcher is not None,
            "browser": self.browser_mon is not None,
            "biometric": self.input_bio_mon is not None,
            "suricata": self.suricata_mon is not None,
            "wazuh": self.wazuh_mon is not None,
            "auth": self.auth_mon is not None,
            "firewall_sync": self.firewall_sync is not None
        }

        # [NEW] 위치 정보 수집 (IP 기반)
        loc = self._get_location()
        if loc:
            meta["location"] = loc

        # [NEW] 물리 네트워크 인터페이스(NIC) 정보 수집
        try:
            import psutil
            interfaces = []
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            io_counters = psutil.net_io_counters(pernic=True)
            for nic_name, nic_addrs in addrs.items():
                ip = next((a.address for a in nic_addrs if getattr(a.family, 'name', '') == 'AF_INET' or a.family == 2), None)
                if ip:
                    nic_stat = stats.get(nic_name)
                    nic_io = io_counters.get(nic_name)
                    interfaces.append({
                        "name": nic_name,
                        "ip": ip,
                        "isup": nic_stat.isup if nic_stat else False,
                        "speed": getattr(nic_stat, 'speed', 0) if nic_stat else 0,
                        "tx": getattr(nic_io, 'bytes_sent', 0) if nic_io else 0,
                        "rx": getattr(nic_io, 'bytes_recv', 0) if nic_io else 0
                    })
            if interfaces:
                meta["interfaces"] = interfaces
        except Exception as e:
            self.logger.warning(f"NIC 정보 수집 실패: {e}")
        
        return meta

    def _get_location(self):
        """공인 IP를 통해 현재 에이전트의 대략적인 위치를 파악합니다."""
        try:
            import requests
            # 여러 개의 백업 서비스를 시도하여 신뢰성을 높임
            apis = [
                "http://ip-api.com/json/",
                "https://ipapi.co/json/",
                "https://ifconfig.co/json"
            ]
            headers = {'User-Agent': 'BeaconGuardian/1.0'}
            
            for api in apis:
                try:
                    resp = requests.get(api, timeout=3, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        # 필드명이 서비스마다 다르므로 유연하게 처리
                        city = data.get('city') or data.get('city_name')
                        country = data.get('country') or data.get('country_name')
                        if city and country:
                            return f"{city}, {country}"
                except:
                    continue
        except:
            pass
        return "Unknown Location"

def main():
    parser = argparse.ArgumentParser(description="Security Monitoring Agent")
    parser.add_argument("--config", default=os.path.join(ROOT_DIR, "config.yaml"), help="Path to config.yaml")
    parser.add_argument("--no-ui", action="store_true", help="설정 UI 없이 바로 에이전트 실행")
    parser.add_argument("--test-ids-v", action="store_true", help="가상 IDS 경보 주입 테스트")
    parser.add_argument("--test-ids-r", action="store_true", help="실제 IDS 탐지 트리거 테스트(curl)")
    parser.add_argument("--test-file", action="store_true", help="파일 시스템 감시 트리거 테스트")
    parser.add_argument("--test-bio", action="store_true", help="가상 행위 이상치 주입 테스트")
    parser.add_argument("--test-ddos", action="store_true", help="가상 DDoS 공격 차단 테스트")
    args = parser.parse_args()

    config_path = args.config

    # 테스트 옵션이 있는지 확인
    test_args = [args.test_ids_v, args.test_ids_r, args.test_file, args.test_bio, args.test_ddos]
    is_test_mode = any(test_args)

    if not args.no_ui and not is_test_mode:
        try:
            from ui.setup_wizard import run_setup
            run_setup(force=True)
            return
        except ImportError:
            try:
                from ui.setup_ui import run_setup
                run_setup(force=True)
                return
            except ImportError:
                print("[Warning] 설정 UI 모듈을 찾을 수 없습니다. 설정 없이 계속합니다.")

    agent = SecurityAgent(config_path=config_path)

    # 테스트 플래그 처리
    if args.test_ids_v: agent.run_test_scenario("ids-v")
    if args.test_ids_r: agent.run_test_scenario("ids-r")
    if args.test_file: agent.run_test_scenario("file")
    if args.test_bio: agent.run_test_scenario("bio")
    if args.test_ddos: agent.run_test_scenario("ddos")
    
    # 만약 테스트 전용으로 실행된 경우 여기서 종료 옵션 (원할 경우 exit())
    if any([args.test_ids_v, args.test_ids_r, args.test_file, args.test_bio]):
        print("\n[INFO] 모든 요청된 테스트 시나리오가 완료되었습니다.")
        # 만약 테스트만 하고 끝내고 싶다면 아래 주석 해제
        # sys.exit(0)

    signal.signal(signal.SIGINT, lambda s, f: agent.stop())
    signal.signal(signal.SIGTERM, lambda s, f: agent.stop())

    agent.run()

if __name__ == "__main__":
    main()
