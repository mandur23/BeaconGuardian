import json
import logging
import os
import threading
import time


class InputBiometricMonitor(threading.Thread):
    """
    키보드/마우스 입력을 로컬 JSONL 파일로 저장합니다.
    - 네트워크 전송 없음
    - 개인정보 이슈를 고려해 필요 시 설정으로 비활성화 권장
    """

    def __init__(self, output_path, flush_interval=2, mouse_move_sample_ms=120):
        super().__init__()
        self.output_path = output_path
        self.flush_interval = max(1, int(flush_interval))
        self.mouse_move_sample_ms = max(10, int(mouse_move_sample_ms))
        self.logger = logging.getLogger("InputBiometricMonitor")
        self.daemon = True
        self.running = True

        self._events = []
        self._lock = threading.Lock()
        self._last_mouse_move_ms = 0
        self._keyboard_listener = None
        self._mouse_listener = None

    def _append_event(self, event_type, data):
        event = {
            "eventType": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        with self._lock:
            self._events.append(event)

    @staticmethod
    def _key_to_category(key):
        """실제 키 문자를 기록하지 않고 카테고리만 반환 (개인정보 보호)."""
        try:
            ch = getattr(key, "char", None)
            if ch is not None:
                if ch.isalpha():
                    return "alpha"
                if ch.isdigit():
                    return "digit"
                return "symbol"
            name = getattr(key, "name", None) or str(key)
            # 특수 키는 이름 기록 가능 (shift, ctrl, alt 등 — 민감 정보 아님)
            safe_specials = {
                "shift", "shift_r", "ctrl_l", "ctrl_r", "alt_l", "alt_r",
                "cmd", "cmd_r", "tab", "caps_lock", "enter", "backspace",
                "delete", "space", "esc", "up", "down", "left", "right",
                "home", "end", "page_up", "page_down", "insert",
                "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9",
                "f10", "f11", "f12",
            }
            name_lower = name.replace("Key.", "").lower()
            if name_lower in safe_specials:
                return name_lower
            return "special"
        except Exception:
            return "unknown"

    def _on_key_press(self, key):
        self._append_event("KEY_PRESS", {"category": self._key_to_category(key)})

    def _on_key_release(self, key):
        self._append_event("KEY_RELEASE", {"category": self._key_to_category(key)})

    def _on_mouse_move(self, x, y):
        now_ms = int(time.time() * 1000)
        if now_ms - self._last_mouse_move_ms < self.mouse_move_sample_ms:
            return
        self._last_mouse_move_ms = now_ms
        self._append_event("MOUSE_MOVE", {"x": x, "y": y})

    def _on_mouse_click(self, x, y, button, pressed):
        self._append_event(
            "MOUSE_CLICK",
            {"x": x, "y": y, "button": str(button), "pressed": bool(pressed)},
        )

    def _on_mouse_scroll(self, x, y, dx, dy):
        self._append_event("MOUSE_SCROLL", {"x": x, "y": y, "dx": dx, "dy": dy})

    def _flush_events(self):
        with self._lock:
            if not self._events:
                return
            batch = self._events
            self._events = []

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "a", encoding="utf-8") as f:
            for row in batch:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _start_listeners(self):
        try:
            from pynput import keyboard, mouse
        except ImportError:
            self.logger.error("pynput 미설치: 입력 생체 수집 비활성화")
            return False

        self._keyboard_listener = keyboard.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release,
        )
        self._mouse_listener = mouse.Listener(
            on_move=self._on_mouse_move,
            on_click=self._on_mouse_click,
            on_scroll=self._on_mouse_scroll,
        )
        self._keyboard_listener.start()
        self._mouse_listener.start()
        return True

    def run(self):
        if not self._start_listeners():
            return
        self.logger.info("Input biometric monitor started (local-only): %s", self.output_path)
        while self.running:
            time.sleep(self.flush_interval)
            try:
                self._flush_events()
            except Exception as e:
                self.logger.error("Failed to flush biometric events: %s", e)

        # 종료 시 잔여 이벤트 저장
        try:
            self._flush_events()
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self._keyboard_listener is not None:
            self._keyboard_listener.stop()
        if self._mouse_listener is not None:
            self._mouse_listener.stop()
