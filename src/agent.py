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

from beacon_client import BeaconClient
from usb_monitor import USBMonitor
from process_monitor import ProcessMonitor
from file_watcher import FileWatcher
from browser_monitor import BrowserMonitor

class SecurityAgent:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.path.join(ROOT_DIR, 'config.yaml')
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.logger = logging.getLogger('SecurityAgent')

        # Initialize Beacon Client
        bc_conf = self.config['beacon']
        self.client = BeaconClient(bc_conf['server_url'], bc_conf['username'], bc_conf['password'])
        
        # Initialize Monitors
        mon_conf = self.config['monitoring']
        path_conf = self.config['paths']
        
        self.usb_mon = USBMonitor(
            callback=self.client.send_event, 
            interval=mon_conf.get('usb_check_interval', 5)
        )
        self.proc_mon = ProcessMonitor(
            callback=self.client.send_event, 
            interval=mon_conf.get('process_check_interval', 5)
        )
        self.file_watcher = FileWatcher(
            callback=self.client.send_event, 
            directories=path_conf.get('watch_dirs', [])
        )
        self.browser_mon = BrowserMonitor(
            callback=self.client.send_event,
            interval=mon_conf.get('browser_check_interval', 30)
        )
        
        self.running = True

    def _load_config(self, path):
        if not os.path.exists(path):
            print(f"Error: Config file not found at {path}")
            sys.exit(1)
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

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

        # Start all monitor threads
        self.usb_mon.start()
        self.net_mon.start()
        self.proc_mon.start()
        self.file_watcher.start()
        self.browser_mon.start()

        self.logger.info("All monitoring threads started.")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.logger.info("Stopping agent gracefully...")
        self.running = False
        
        # Stop all threads
        self.usb_mon.stop()
        self.net_mon.stop()
        self.proc_mon.stop()
        self.file_watcher.stop()
        self.browser_mon.stop()
        
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
            from setup_ui import run_setup
            run_setup(force=True)
            return
        except ImportError:
            print("[Warning] setup_ui.py를 찾을 수 없습니다. 설정 없이 계속합니다.")

    agent = SecurityAgent(config_path=config_path)

    signal.signal(signal.SIGINT, lambda s, f: agent.stop())
    signal.signal(signal.SIGTERM, lambda s, f: agent.stop())

    agent.run()

if __name__ == "__main__":
    main()
