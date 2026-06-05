import json
import logging
import platform
import shutil
import subprocess
import threading
import time


class WazuhMonitor(threading.Thread):
    ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"

    def __init__(self, callback, wazuh_container="single-node-wazuh.manager-1", min_level=5):
        super().__init__()
        self.callback = callback

        import os
        env_container = os.environ.get("WAZUH_CONTAINER_NAME")
        self.container = (env_container or wazuh_container or "").strip()

        self.min_level = min_level
        self.logger = logging.getLogger("WazuhMonitor")
        self.stop_event = threading.Event()
        self.process = None
        self.daemon = True

    @staticmethod
    def _docker_available():
        return shutil.which("docker") is not None

    def _use_docker(self):
        name = (self.container or "").strip().lower()
        if name in ("", "local", "none", "host"):
            return platform.system() == "Windows" and self._docker_available()
        return True

    def _build_tail_cmd(self):
        if self._use_docker():
            if not self._docker_available():
                return None
            container = self.container
            if not container or container.lower() in ("local", "none", "host"):
                container = "single-node-wazuh.manager-1"
            return [
                "docker",
                "exec",
                container,
                "tail",
                "-F",
                self.ALERTS_PATH,
            ]
        if platform.system() == "Windows":
            self.logger.error(
                "Windows에서 Wazuh 로컬 tail은 지원되지 않습니다. "
                "wazuh.container_name에 Docker 컨테이너 이름을 지정하세요."
            )
            return None
        return ["tail", "-F", self.ALERTS_PATH]

    def run(self):
        cmd = self._build_tail_cmd()
        if not cmd:
            self.logger.error("WazuhMonitor: tail 명령을 구성할 수 없습니다.")
            return

        mode = "docker" if cmd[0] == "docker" else "local"
        target = self.container if mode == "docker" else self.ALERTS_PATH
        self.logger.info("WazuhMonitor started (%s mode: %s)", mode, target)

        while not self.stop_event.is_set():
            try:
                creationflags = 0
                if platform.system() == "Windows":
                    creationflags = 0x08000000

                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    creationflags=creationflags,
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
                self.logger.error("Wazuh tailing failed: %s", e)

            if not self.stop_event.is_set():
                self.logger.info("Retrying Wazuh connection in 5 seconds...")
                time.sleep(5)

    def _process_alert(self, line):
        try:
            alert = json.loads(line)
            rule = alert.get("rule", {})
            level = rule.get("level", 0)

            if level < self.min_level:
                return

            event_type = "WAZUH_ALERT"
            severity = self._map_severity(level)
            description = rule.get("description", "Unknown Wazuh Alert")
            metadata = alert

            if "syscheck" in alert:
                event_type = "FILE_CHANGE"

            beacon_event = {
                "eventType": event_type,
                "severity": severity,
                "summary": f"[Wazuh] L{level}: {description}",
                "description": alert.get("full_log", description),
                "metadata": metadata,
            }

            self.callback(beacon_event)

        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.error("Error parsing Wazuh alert: %s", e)

    def _map_severity(self, level):
        if level >= 12:
            return "CRITICAL"
        if level >= 8:
            return "HIGH"
        if level >= 5:
            return "MEDIUM"
        return "LOW"

    def stop(self):
        self.stop_event.set()
        if self.process:
            try:
                self.process.terminate()
                self.process.kill()
            except Exception:
                pass
        self.join(timeout=2)
