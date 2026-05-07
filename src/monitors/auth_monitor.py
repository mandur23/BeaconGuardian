import win32evtlog
import win32evtlogutil
import win32security
import win32con
import threading
import time
import logging
from datetime import datetime

class AuthMonitor(threading.Thread):
    """
    Windows Security Event Log를 모니터링하여 로그온 실패(Event ID 4625)를 탐지합니다.
    관리자 권한으로 실행되어야 합니다.
    """
    def __init__(self, callback, interval=3):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('AuthMonitor')
        self.running = True
        self.daemon = True
        
        self.log_name = "Security"
        self.target_event_id = 4625 # Logon Failure
        
        try:
            self.hand = win32evtlog.OpenEventLog(None, self.log_name)
            self.last_record_count = win32evtlog.GetEventLogRecordCount(self.hand)
            self.logger.info(f"AuthMonitor initialized. Starting at record count: {self.last_record_count}")
        except Exception as e:
            self.logger.error(f"Failed to open Security Event Log: {e}. Are you running as Administrator?")
            self.hand = None

    def run(self):
        if not self.hand:
            self.logger.error("AuthMonitor aborted due to permission issues.")
            return

        self.logger.info("Windows Auth Monitor thread started.")
        while self.running:
            try:
                num_records = win32evtlog.GetEventLogRecordCount(self.hand)
                if num_records > self.last_record_count:
                    # New records added
                    self._check_new_records(num_records)
                self.last_record_count = num_records
            except Exception as e:
                self.logger.error(f"Error in AuthMonitor loop: {e}")
            
            time.sleep(self.interval)

    def _check_new_records(self, current_total):
        # 뒤에서부터 새로운 레코드들을 읽어옴
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        try:
            records = win32evtlog.ReadEventLog(self.hand, flags, 0)
            for event in records:
                # Event ID parsing (Event ID in EventLog is 32-bit, lower 16 bits is the ID)
                event_id = event.EventID & 0xFFFF
                
                if event_id == self.target_event_id:
                    self._process_failure_event(event)
                
                # 이미 읽은 레코드 수만큼 체크했다면 종료 (단순화된 로직)
                # 실제로는 Index를 추적하는 것이 더 정확함
        except Exception as e:
            self.logger.error(f"Error reading event log: {e}")

    def _process_failure_event(self, event):
        """
        Event ID 4625 데이터 파싱
        StringInserts 인덱스 (Windows 10/11 기준):
        5: TargetUserName
        6: TargetDomainName
        13: WorkstationName
        18: IpAddress (Source Network Address)
        19: IpPort (Source Port)
        """
        try:
            data = event.StringInserts
            user = data[5] if len(data) > 5 else "Unknown"
            source_ip = data[18].strip() if len(data) > 18 else "-"
            # '-' 인 경우는 로컬 로그온 시도임
            if source_ip == "-" or source_ip == "::1" or source_ip == "127.0.0.1":
                source_ip = "Local/Internal"

            description = f"Logon Failure detected: Account='{user}', Source='{source_ip}'"
            
            event_data = {
                "eventType": "USER_LOGIN_FAILED",
                "severity": "high",
                "summary": "Unauthorized Access Attempt",
                "description": description,
                "metadata": {
                    "user": user,
                    "source_ip": source_ip,
                    "event_id": 4625,
                    "timestamp": datetime.now().isoformat(),
                    "log_type": "Windows Security Log"
                }
            }
            
            self.logger.warning(f"🚨 [AuthMonitor] {description}")
            self.callback(event_data)
        except Exception as e:
            self.logger.error(f"Error processing 4625 event: {e}")

    def stop(self):
        self.running = False
        if self.hand:
            win32evtlog.CloseEventLog(self.hand)

