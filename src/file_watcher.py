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
    def __init__(self, callback, directories):
        super().__init__()
        self.callback = callback
        self.directories = directories
        self.observer = Observer()
        self.logger = logging.getLogger('FileWatcher')
        self.last_events = {}  # (path, event_type) -> timestamp for deduplication
        self.dedup_interval = 1.0  # 1 second deduplication window
        self.daemon = True

    def _event_callback(self, event_type, path, is_directory, dest_path=None):
        now = time.time()
        key = (path, event_type)
        if key in self.last_events and (now - self.last_events[key]) < self.dedup_interval:
            return
        self.last_events[key] = now

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
            "severity": "medium",
            "description": description,
            "metadata": metadata
        }
        self.callback(event)

    def run(self):
        self.logger.info("File Watcher thread started.")
        handler = FileChangeHandler(self._event_callback, self.logger)
        for directory in self.directories:
            expanded_dir = os.path.expandvars(directory)
            # Windows에서 /etc, /home 등 POSIX 경로는 존재하지 않음 — 경고 스팸 방지
            if os.name == "nt" and expanded_dir.startswith("/"):
                continue
            if not os.path.exists(expanded_dir):
                self.logger.warning(f"Directory does not exist: {expanded_dir}")
                continue
                
            try:
                self.observer.schedule(handler, expanded_dir, recursive=True)
                self.logger.info(f"Watching directory: {expanded_dir}")
            except Exception as e:
                self.logger.error(f"Failed to watch {expanded_dir}: {e}")
        
        if self.observer.emitters:
            self.observer.start()
            while self.observer.is_alive():
                self.observer.join(1)
        else:
            self.logger.error("No valid directories to watch. Observer not started.")

    def stop(self):
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
