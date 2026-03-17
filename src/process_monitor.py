import psutil
import time
import logging
import threading

class ProcessMonitor(threading.Thread):
    def __init__(self, callback, interval=5):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('ProcessMonitor')
        self.last_pids = {p.pid for p in psutil.process_iter(['pid'])}
        self.running = True
        self.daemon = True

    def run(self):
        self.logger.info("Process Monitor thread started.")
        while self.running:
            try:
                events = self.check_events()
                for event in events:
                    self.callback(event)
                
                login_events = self.check_login_events()
                for event in login_events:
                    self.callback(event)
            except Exception as e:
                self.logger.error(f"Error in process monitor: {e}")
            time.sleep(self.interval)

    def check_events(self):
        current_pids = {p.pid for p in psutil.process_iter(['pid'])}
        events = []

        # New processes
        added = current_pids - self.last_pids
        for pid in added:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = "unknown"
                
                events.append({
                    "eventType": "PROCESS_START",
                    "severity": "low",
                    "description": f"Process started: {name} (PID: {pid})",
                    "metadata": {
                        "pid": pid,
                        "name": name,
                        "exe": exe,
                        "timestamp": time.time()
                    }
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Terminated processes
        removed = self.last_pids - current_pids
        for pid in removed:
            events.append({
                "eventType": "PROCESS_STOP",
                "severity": "low",
                "description": f"Process stopped (PID: {pid})",
                "metadata": {
                    "pid": pid,
                    "timestamp": time.time()
                }
            })

        self.last_pids = current_pids
        return events

    def check_login_events(self):
        """Monitor user login/logout events via psutil.users()"""
        try:
            users = psutil.users()
            events = []
            for user in users:
                events.append({
                    "eventType": "USER_LOGIN",
                    "severity": "low",
                    "description": f"User active: {user.name}",
                    "metadata": {
                        "user": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": user.started,
                        "timestamp": time.time()
                    }
                })
            return events
        except Exception as e:
            self.logger.error(f"Error checking login events: {e}")
            return []

    def stop(self):
        self.running = False
