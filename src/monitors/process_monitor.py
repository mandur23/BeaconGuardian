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
        self.last_processes = self._snapshot_processes()
        self.last_pids = set(self.last_processes.keys())
        self.last_users = self._get_user_set()
        self.running = True
        self.daemon = True

    @staticmethod
    def _get_user_set():
        """현재 로그인 사용자를 (name, terminal, host) 튜플 집합으로 반환."""
        try:
            return {(u.name, u.terminal, u.host) for u in psutil.users()}
        except Exception:
            return set()

    @staticmethod
    def _snapshot_processes():
        processes = {}
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'ppid']):
            try:
                info = proc.info
                processes[proc.pid] = {
                    "pid": proc.pid,
                    "process_name": info.get("name") or "unknown",
                    "image_path": info.get("exe") or "unknown",
                    "parent_pid": info.get("ppid") or 0,
                    "user": info.get("username") or "unknown",
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

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
        current_processes = self._snapshot_processes()
        current_pids = set(current_processes.keys())
        events = []

        # New processes
        added = current_pids - self.last_pids
        for pid in added:
            try:
                proc_info = current_processes.get(pid, {})
                name = proc_info.get("process_name", "unknown")
                exe = proc_info.get("image_path", "unknown")
                
                events.append({
                    "eventType": "PROCESS_START",
                    "severity": "low",
                    "description": f"Process started: {name} (PID: {pid})",
                    "metadata": {
                        "pid": pid,
                        "process_name": name,
                        "image_path": exe,
                        "parent_pid": proc_info.get("parent_pid", 0),
                        "user": proc_info.get("user", "unknown"),
                        "timestamp": time.time()
                    }
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Terminated processes
        removed = self.last_pids - current_pids
        for pid in removed:
            proc_info = self.last_processes.get(pid, {})
            process_name = proc_info.get("process_name", "unknown")
            events.append({
                "eventType": "PROCESS_STOP",
                "severity": "low",
                "description": f"Process stopped: {process_name} (PID: {pid})",
                "metadata": {
                    "pid": pid,
                    "process_name": process_name,
                    "image_path": proc_info.get("image_path", "unknown"),
                    "parent_pid": proc_info.get("parent_pid", 0),
                    "user": proc_info.get("user", "unknown"),
                    "timestamp": time.time()
                }
            })

        self.last_processes = current_processes
        self.last_pids = current_pids
        return events

    def check_login_events(self):
        """Monitor user login/logout events via psutil.users() — 변경분만 전송."""
        try:
            current_users = self._get_user_set()
            events = []

            # 새 로그인
            for key in current_users - self.last_users:
                name, terminal, host = key
                events.append({
                    "eventType": "USER_LOGIN",
                    "severity": "low",
                    "description": f"User logged in: {name}",
                    "metadata": {
                        "user": name,
                        "terminal": terminal,
                        "host": host,
                        "timestamp": time.time()
                    }
                })

            # 로그아웃
            for key in self.last_users - current_users:
                name, terminal, host = key
                events.append({
                    "eventType": "USER_LOGOUT",
                    "severity": "low",
                    "description": f"User logged out: {name}",
                    "metadata": {
                        "user": name,
                        "terminal": terminal,
                        "host": host,
                        "timestamp": time.time()
                    }
                })

            self.last_users = current_users
            return events
        except Exception as e:
            self.logger.error(f"Error checking login events: {e}")
            return []

    def stop(self):
        self.running = False
