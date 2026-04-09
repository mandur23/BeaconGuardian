import threading
import time
import logging
import json
import os
import subprocess
import signal
import platform

class SuricataMonitor(threading.Thread):
    def __init__(self, callback, config):
        super().__init__()
        self.callback = callback
        self.config = config
        self.logger = logging.getLogger('SuricataMonitor')
        self.stop_event = threading.Event()
        self.daemon = True
        
        self.binary_path = config.get('binary_path', r"C:\Program Files\Suricata\suricata.exe")
        self.config_path = config.get('config_path', r"C:\Program Files\Suricata\suricata.yaml")
        self.eve_log_path = config.get('eve_log_path', r"C:\Program Files\Suricata\log\eve.json")
        self.interface = config.get('interface', 'any')
        
        self.process = None
        self._last_position = 0
        self._detected_interface = None

    def run(self):
        self.logger.info("수리카타 모니터 시작 준비 중...")
        
        # 1. 수리카타 프로세스 시작 (관리 모드인 경우)
        if self.config.get('manage_process', True):
            self._start_suricata_process()
            
        # 2. 로그 파일 존재 확인 및 초기 위치 설정
        if os.path.exists(self.eve_log_path):
            self._last_position = os.path.getsize(self.eve_log_path)
            self.logger.info(f"기존 로그 발견. 현재 위치: {self._last_position}")
        else:
            self.logger.warning(f"로그 파일을 찾을 수 없습니다: {self.eve_log_path}. 생성을 기다립니다.")

        # 3. 메인 루프: 파일 테일링
        while not self.stop_event.is_set():
            try:
                if os.path.exists(self.eve_log_path):
                    self._tail_log_file()
                
                # 프로세스 상태 체크
                if self.process and self.process.poll() is not None:
                    self.logger.error("수리카타 프로세스가 예기치 않게 종료되었습니다.")
                    if not self.stop_event.is_set():
                        self.logger.info("재시작 시도 중...")
                        self._start_suricata_process()
                        
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"수리카타 모니터 루프 오류: {e}")
                time.sleep(5)

    def _get_active_interface_guid(self):
        """인터넷 연결이 활성 상태인 네트워크 카드의 GUID를 자동으로 찾습니다 (Windows 전용)"""
        try:
            if platform.system() != "Windows":
                return "any"

            # 파워쉘을 통해 'Up' 상태인 카드 중 DeviceID(GUID) 추출
            cmd = "powershell -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1 -ExpandProperty DeviceID\""
            result = subprocess.check_output(cmd, shell=True, text=True).strip()
            
            if result and result.startswith('{'):
                guid = f"\\Device\\NPF_{result}"
                self.logger.info(f"활성 네트워크 인터페이스 자동 감지 성공: {guid}")
                return guid
            
            self.logger.warning("활성 네트워크 인터페이스를 자동으로 찾지 못했습니다. 'any'로 시도합니다.")
            return "any"
        except Exception as e:
            self.logger.error(f"인터페이스 자동 감지 중 오류 발생: {e}")
            return "any"

    def _start_suricata_process(self):
        if not os.path.exists(self.binary_path):
            self.logger.error(f"수리카타 실행 파일을 찾을 수 없습니다: {self.binary_path}")
            return

        # 인터페이스 결정 (auto 모드 처리)
        target_interface = self.interface
        if target_interface.lower() == "auto" or not target_interface:
            if not self._detected_interface:
                self._detected_interface = self._get_active_interface_guid()
            target_interface = self._detected_interface

        # 명령줄 인자 구성
        cmd = [
            self.binary_path,
            "-c", self.config_path,
            "-i", target_interface
        ]
        
        try:
            self.logger.info(f"수리카타 실행: {' '.join(cmd)}")
            # CREATE_NO_WINDOW 플래그 (Windows용 전용)
            creation_flags = 0
            if platform.system() == "Windows":
                creation_flags = 0x08000000 # CREATE_NO_WINDOW
                
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=creation_flags
            )
            
            # 별도의 스레드로 stderr를 모니터링하여 오류 발생 시 기록
            def log_stderr(proc):
                for line in proc.stderr:
                    line = line.strip()
                    if line:
                        self.logger.error(f"Suricata [stderr]: {line}")
            
            threading.Thread(target=log_stderr, args=(self.process,), daemon=True).start()
            
            self.logger.info(f"수리카타 프로세스 시작됨 (PID: {self.process.pid})")
        except Exception as e:
            self.logger.error(f"수리카타 프로세스 시작 실패: {e}")

    def _tail_log_file(self):
        current_size = os.path.getsize(self.eve_log_path)
        
        if current_size < self._last_position:
            self.logger.info("로그 파일이 교체(truncate)된 것을 감지했습니다. 처음부터 읽습니다.")
            self._last_position = 0
            
        if current_size > self._last_position:
            with open(self.eve_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        self._process_line(line)
                self._last_position = f.tell()

    def _process_line(self, line):
        try:
            data = json.loads(line)
            event_type = data.get("event_type")
            
            # 불필요한 이벤트 필터링 (stats 등)
            if event_type in ["stats", "flow", "netflow"]:
                return
                
            # 서버 전송용 정보 추출
            # alert가 있으면 중점적으로, 그 외 로그도 필요시 전송
            self.callback(data) 
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.error(f"로그 라인 처리 오류: {e}")

    def stop(self):
        self.logger.info("수리카타 모니터 중단 중...")
        self.stop_event.set()
        if self.process:
            try:
                if platform.system() == "Windows":
                    self.process.terminate()
                else:
                    os.kill(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=5)
            except Exception as e:
                self.logger.warning(f"수리카타 프로세스 종료 중 오류: {e}")
                if self.process:
                    self.process.kill()
