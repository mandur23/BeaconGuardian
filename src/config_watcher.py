"""
config.yaml 핫 리로드 — watchdog 기반.

파일 변경 감지 시 콜백을 호출하여 에이전트 설정을 동적 반영합니다.
짧은 시간 내 연속 변경(에디터 임시 저장 등)은 디바운스 처리합니다.
"""

import logging
import os
import threading
import time

import yaml

logger = logging.getLogger("ConfigWatcher")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _WATCHDOG_AVAILABLE = False


class _ConfigChangeHandler(FileSystemEventHandler):
    """config.yaml 변경 감지 핸들러 (디바운스 포함)."""

    def __init__(self, config_path, callback, debounce=2.0):
        super().__init__()
        self._config_path = os.path.normpath(config_path)
        self._config_name = os.path.basename(config_path)
        self._callback = callback
        self._debounce = debounce
        self._timer = None
        self._lock = threading.Lock()

    def on_modified(self, event):
        if event.is_directory:
            return
        changed = os.path.normpath(event.src_path)
        if changed != self._config_path:
            return
        self._schedule_reload()

    def on_created(self, event):
        # 일부 에디터는 삭제 후 재생성으로 저장
        if event.is_directory:
            return
        changed = os.path.normpath(event.src_path)
        if changed != self._config_path:
            return
        self._schedule_reload()

    def _schedule_reload(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce, self._do_reload)
            self._timer.daemon = True
            self._timer.start()

    def _do_reload(self):
        logger.info("config.yaml changed — reloading")
        try:
            self._callback()
        except Exception as e:
            logger.error("Hot reload callback failed: %s", e)


class ConfigWatcher:
    """
    config.yaml 변경을 감시하고 콜백을 호출합니다.

    사용법:
        watcher = ConfigWatcher(config_path, on_reload_callback)
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(self, config_path: str, callback, debounce: float = 2.0):
        """
        Args:
            config_path: 감시할 config.yaml 절대 경로
            callback: 설정 변경 시 호출할 함수 (인자 없음)
            debounce: 연속 변경 무시 시간 (초)
        """
        self._config_path = os.path.abspath(config_path)
        self._callback = callback
        self._debounce = debounce
        self._observer = None
        self._running = False

        if not _WATCHDOG_AVAILABLE:
            logger.warning("watchdog 미설치 — 폴링 모드로 핫 리로드합니다")

    def start(self):
        if self._running:
            return

        self._running = True

        if _WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_polling()

        logger.info("ConfigWatcher started: %s (debounce=%.1fs)", self._config_path, self._debounce)

    def stop(self):
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
        logger.info("ConfigWatcher stopped")

    def _start_watchdog(self):
        watch_dir = os.path.dirname(self._config_path)
        handler = _ConfigChangeHandler(self._config_path, self._callback, self._debounce)
        self._observer = Observer()
        self._observer.schedule(handler, watch_dir, recursive=False)
        self._observer.daemon = True
        self._observer.start()

    def _start_polling(self):
        """watchdog 없을 때 폴링 폴백."""
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

    def _poll_loop(self):
        last_mtime = self._get_mtime()
        while self._running:
            time.sleep(max(3, self._debounce))
            try:
                mtime = self._get_mtime()
                if mtime and mtime != last_mtime:
                    last_mtime = mtime
                    logger.info("config.yaml changed (poll) — reloading")
                    self._callback()
            except Exception as e:
                logger.error("Config poll error: %s", e)

    def _get_mtime(self):
        try:
            return os.path.getmtime(self._config_path)
        except OSError:
            return None


def load_yaml_safe(path: str) -> dict:
    """YAML 파일을 안전하게 읽어 dict로 반환합니다."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
