import time
import logging
import os
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, callback, logger):
        self.callback = callback
        self.logger = logger
        self.max_file_size = 1024 * 1024 * 1024  # 1GB

    def _is_large_file(self, path):
        try:
            if os.path.isfile(path) and os.path.getsize(path) >= self.max_file_size:
                return True
        except (OSError, FileNotFoundError):
            pass
        return False

    def on_modified(self, event):
        if self._is_large_file(event.src_path):
            return
        self.callback("FILE_MODIFIED", event.src_path, event.is_directory)

    def on_created(self, event):
        if self._is_large_file(event.src_path):
            return
        self.callback("FILE_CREATED", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self.callback("FILE_DELETED", event.src_path, event.is_directory)

    def on_moved(self, event):
        if self._is_large_file(event.dest_path):
            return
        self.callback("FILE_MOVED", event.src_path, event.is_directory, dest_path=event.dest_path)

class FileWatcher(threading.Thread):
    def __init__(self, callback, directories, ignore_dirs=None, ignore_extensions=None, critical_dirs=None, critical_extensions=None):
        super().__init__()
        self.callback = callback
        self.directories = directories
        self.ignore_dirs = ignore_dirs or []
        self.ignore_extensions = [ext.lower() for ext in (ignore_extensions or [])]
        self.critical_dirs = critical_dirs or []
        self.critical_extensions = [ext.lower() for ext in (critical_extensions or [])]
        
        self.observer = Observer()
        self.logger = logging.getLogger('FileWatcher')
        self.last_events = {}  # (path, event_type) -> timestamp for deduplication
        self.dedup_interval = 1.0  # 1 second deduplication window
        self.daemon = True

    def _should_ignore(self, path):
        # 1. 확장자 기반 필터링
        _, ext = os.path.splitext(path)
        if ext.lower() in self.ignore_extensions:
            return True
        
        # 2. 경로 기반 필터링
        normalized_path = path.replace('\\', '/')
        for ignore_dir in self.ignore_dirs:
            normalized_ignore = ignore_dir.replace('\\', '/')
            if normalized_ignore in normalized_path:
                return True
        return False

    def _get_severity(self, event_type, path):
        # 기본 위험도 설정
        severity = "low"
        
        # 파일 삭제는 기본적으로 좀 더 중요하게 취급
        if event_type == "FILE_DELETED":
            severity = "medium"
            
        # 중요 확장자 체크
        _, ext = os.path.splitext(path)
        if ext.lower() in self.critical_extensions:
            return "high" if event_type == "FILE_DELETED" else "medium"
            
        # 중요 경로 체크
        normalized_path = path.replace('\\', '/')
        for crit_dir in self.critical_dirs:
            normalized_crit = crit_dir.replace('\\', '/')
            if normalized_crit in normalized_path:
                return "high"
        
        return severity

    def _event_callback(self, event_type, path, is_directory, dest_path=None):
        # 0. 무시 대상 여부 확인
        if self._should_ignore(path):
            return
        if dest_path and self._should_ignore(dest_path):
            return

        now = time.time()
        key = (path, event_type)
        if key in self.last_events and (now - self.last_events[key]) < self.dedup_interval:
            return
        self.last_events[key] = now

        # 오래된 중복 제거 항목 정리 (1000개 초과 시)
        if len(self.last_events) > 1000:
            cutoff = now - self.dedup_interval * 2
            self.last_events = {k: v for k, v in self.last_events.items() if v > cutoff}

        description = f"{'Directory' if is_directory else 'File'} {event_type.split('_')[1].lower()}: {path}"
        if dest_path:
            description += f" to {dest_path}"

        metadata = {
            "path": path,
            "event_type": event_type.split('_')[1].lower(),
            "is_directory": is_directory,
            "timestamp": datetime.now().isoformat()
        }
        if dest_path:
            metadata["dest_path"] = dest_path

        event = {
            "eventType": event_type,
            "severity": self._get_severity(event_type, path),
            "description": description,
            "metadata": metadata
        }
        self.callback(event)

    def run(self):
        self.logger.info("File Watcher thread started.")
        self.handler = FileChangeHandler(self._event_callback, self.logger)
        for directory in self.directories:
            self._schedule_watch(directory)
        
        if self.observer.emitters:
            self.observer.start()
            while self.observer.is_alive():
                self.observer.join(1)
        else:
            self.logger.error("No valid directories to watch. Observer not started.")

    def _schedule_watch(self, directory):
        """디렉토리를 옵저버에 등록합니다."""
        expanded_dir = os.path.expandvars(directory)
        if os.name == "nt" and expanded_dir.startswith("/"):
            return
        if not os.path.exists(expanded_dir):
            self.logger.warning(f"Directory does not exist: {expanded_dir}")
            return
            
        try:
            self.observer.schedule(self.handler, expanded_dir, recursive=True)
            self.logger.info(f"Watching directory: {expanded_dir}")
        except Exception as e:
            self.logger.error(f"Failed to watch {expanded_dir}: {e}")

    def add_watch_path(self, path):
        """실행 중에 새로운 감시 경로를 추가합니다. (예: USB 드라이브)"""
        if not self.observer.is_alive():
            self.directories.append(path)
            return
            
        self.logger.info(f"Adding new watch path dynamically: {path}")
        self._schedule_watch(path)

    def stop(self):
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
