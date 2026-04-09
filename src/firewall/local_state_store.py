import json
import logging
import os
import threading

logger = logging.getLogger(__name__)


class LocalStateStore:
    """로컬 revision·규칙 id·채널 B 커서(`last_command_id`)를 JSON으로 유지합니다."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def _default(self):
        return {
            "last_revision": 0,
            "local_rule_ids": [],
            "last_command_id": "",
        }

    def _normalize(self, data: dict) -> dict:
        data.setdefault("last_revision", 0)
        data.setdefault("local_rule_ids", [])
        data.setdefault("last_command_id", "")
        data["last_revision"] = int(data["last_revision"])
        if not isinstance(data["local_rule_ids"], list):
            data["local_rule_ids"] = []
        if data["last_command_id"] is None:
            data["last_command_id"] = ""
        else:
            data["last_command_id"] = str(data["last_command_id"])
        return data

    def _load_nolock(self) -> dict:
        if not os.path.isfile(self.path):
            return self._default()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return self._default()
            return self._normalize(data)
        except Exception as e:
            logger.warning("LocalStateStore load failed: %s", e)
            return self._default()

    def _save_nolock(self, data: dict) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def load(self) -> dict:
        with self._lock:
            return dict(self._load_nolock())

    def save(self, data: dict) -> None:
        with self._lock:
            self._save_nolock(self._normalize(dict(data)))

    def merge_update(self, partial: dict) -> dict:
        """부분 갱신(스레드 안전). A/B 동시 사용 시 덮어쓰기 충돌 방지."""
        with self._lock:
            data = self._load_nolock()
            for k, v in partial.items():
                data[k] = v
            self._save_nolock(self._normalize(data))
            return dict(data)
