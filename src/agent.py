import yaml
import time
import logging
import logging.handlers
import signal
import sys
import argparse
import os

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
        self.client = BeaconClient(
            bc_conf['server_url'],
            bc_conf['username'],
            bc_conf['password'],
            agent_name=ag_conf.get('agent_name', 'BeaconGuardian'),
            agent_version=ag_conf.get('agent_version', '1.0.0'),
            heartbeat_interval_seconds=ag_conf.get('heartbeat_interval_seconds', 60),
            tls=bc_conf.get('tls', {}),
            ip_selection=bc_conf.get('ip_selection', 'outbound'),
            jwt_refresh_before_exp_seconds=bc_conf.get('jwt_refresh_before_exp_seconds', 90),
            admin_usernames=ui_conf.get('admin_usernames'),
        )
        
        # Initialize Monitors — collectors 설정에 따라 선택적 활성화
        mon_conf = self.config['monitoring']
        path_conf = self.config['paths']
        collectors = self.config.get('collectors', {})

        self.usb_mon = None
        if collectors.get('usb', True):
            self.usb_mon = USBMonitor(
                callback=self.client.send_event,
                interval=mon_conf.get('usb_check_interval', 5)
            )

        self.net_mon = None
        if collectors.get('network', True):
            self.net_mon = NetworkMonitor(
                callback=self.client.send_traffic,
                interval=mon_conf.get('network_check_interval', 10)
            )

        self.proc_mon = None
        if collectors.get('process', True):
            self.proc_mon = ProcessMonitor(
                callback=self.client.send_event,
                interval=mon_conf.get('process_check_interval', 5)
            )

        self.file_watcher = None
        if collectors.get('filesystem', True):
            self.file_watcher = FileWatcher(
                callback=self.client.send_event,
                directories=path_conf.get('watch_dirs', [])
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
                flush_interval=mon_conf.get('biometric_flush_interval', 2),
                mouse_move_sample_ms=mon_conf.get('mouse_move_sample_ms', 120),
            )
        
        self.running = True

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
                     self.file_watcher, self.browser_mon, self.input_bio_mon):
            if mon is not None:
                mon.start()

        self.logger.info("All monitoring threads started.")

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
                     self.file_watcher, self.browser_mon, self.input_bio_mon):
            if mon is not None:
                mon.stop()

        # 서버에 연결 해제 알림 후 민감 정보 정리
        self.client.disconnect()
        self.client.stop_heartbeat()
        self.client.clear_credentials()

        self.logger.info("Agent stopped.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Security Monitoring Agent")
    parser.add_argument("--config", default=os.path.join(ROOT_DIR, "config.yaml"), help="Path to config.yaml")
    parser.add_argument("--no-ui", action="store_true", help="설정 UI 없이 바로 에이전트 실행")
    args = parser.parse_args()

    config_path = args.config

    if not args.no_ui:
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

    signal.signal(signal.SIGINT, lambda s, f: agent.stop())
    signal.signal(signal.SIGTERM, lambda s, f: agent.stop())

    agent.run()

if __name__ == "__main__":
    main()
