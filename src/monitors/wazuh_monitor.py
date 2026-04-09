import threading
import subprocess
import json
import logging
import time

class WazuhMonitor(threading.Thread):
    def __init__(self, callback, wazuh_container="single-node-wazuh.manager-1", min_level=5):
        super().__init__()
        self.callback = callback
        
        # [MOD] 환경 변수가 있으면 우선 사용 (Docker 연동 최적화)
        import os
        env_container = os.environ.get("WAZUH_CONTAINER_NAME")
        self.container = env_container if env_container else wazuh_container
        
        self.min_level = min_level
        self.logger = logging.getLogger('WazuhMonitor')
        self.stop_event = threading.Event()
        self.process = None
        self.daemon = True

    def run(self):
        self.logger.info(f"WazuhMonitor started. Tailing alerts from container {self.container}...")
        
        while not self.stop_event.is_set():
            try:
                cmd = [
                    "docker", "exec", self.container,
                    "tail", "-F", "/var/ossec/logs/alerts/alerts.json"
                ]
                
                # Windows 환경에서 subprocess 콘솔 창 숨기기
                creationflags = 0
                import platform
                if platform.system() == "Windows":
                    creationflags = 0x08000000 # CREATE_NO_WINDOW
                
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    creationflags=creationflags
                )

                while True:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    line = line.strip()
                    if line:
                        self._process_alert(line)

                    if self.stop_event.is_set():
                        break

            except Exception as e:
                self.logger.error(f"Wazuh tailing failed: {e}")
            
            if not self.stop_event.is_set():
                self.logger.info("Retrying connection to Wazuh container in 5 seconds...")
                time.sleep(5)

    def _process_alert(self, line):
        try:
            alert = json.loads(line)
            rule = alert.get("rule", {})
            level = rule.get("level", 0)

            # PRO 판단: 노이즈를 줄이기 위해 설정된 최소 레벨 미만 필터링
            if level < self.min_level:
                return

            event_type = "WAZUH_ALERT"
            severity = self._map_severity(level)
            description = rule.get("description", "Unknown Wazuh Alert")
            
            # 원본 알림(Raw Payload)을 metadata에 그대로 보존하여 UI 및 서버가 파싱할 수 있게 함
            metadata = alert

            if "syscheck" in alert:
                event_type = "FILE_CHANGE" # Wazuh FIM 이벤트를 맵핑
                
            beacon_event = {
                "eventType": event_type,
                "severity": severity,
                "summary": f"[Wazuh] L{level}: {description}",
                "description": alert.get("full_log", description),
                "metadata": metadata
            }

            self.callback(beacon_event)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.error(f"Error parsing Wazuh alert: {e}")

    def _map_severity(self, level):
        if level >= 12: return "CRITICAL"
        if level >= 8: return "HIGH"
        if level >= 5: return "MEDIUM"
        return "LOW"

    def stop(self):
        self.stop_event.set()
        if self.process:
            try:
                self.process.terminate()
                self.process.kill()
            except:
                pass
        self.join(timeout=2)
