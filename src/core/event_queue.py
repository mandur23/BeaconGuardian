"""
오프라인 이벤트 큐 — SQLite 기반.

서버 전송 실패 시 이벤트를 로컬 DB에 저장하고,
백그라운드 스레드가 주기적으로 재전송을 시도합니다.

테이블 구조:
  pending_events(id, kind, payload_json, endpoint, created_at, retry_count)
  kind: "event" | "traffic"
"""

import json
import logging
import os
import sqlite3
import threading
import time

logger = logging.getLogger("EventQueue")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL DEFAULT 'event',
    payload_json TEXT    NOT NULL,
    endpoint     TEXT    NOT NULL DEFAULT '',
    created_at   REAL    NOT NULL,
    retry_count  INTEGER NOT NULL DEFAULT 0
);
"""

_MAX_QUEUE_SIZE = 10000
_MAX_RETRY = 20


class EventQueue:
    """SQLite 기반 이벤트 오프라인 버퍼."""

    def __init__(
        self,
        db_path: str,
        flush_interval: int = 15,
        batch_size: int = 50,
    ):
        self.db_path = db_path
        self.flush_interval = max(5, int(flush_interval))
        self.batch_size = max(1, min(200, int(batch_size)))

        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

        self._send_event_fn = None
        self._send_traffic_fn = None
        self._flush_thread = None
        self._running = False

        pending = self._pending_count()
        if pending:
            logger.info("EventQueue loaded: %d pending events in %s", pending, db_path)

    # ── 공용 API ─────────────────────────────────────────────────────────

    def set_senders(self, send_event_fn, send_traffic_fn):
        """BeaconClient의 실제 전송 함수를 등록합니다."""
        self._send_event_fn = send_event_fn
        self._send_traffic_fn = send_traffic_fn

    def enqueue_event(self, payload: dict, endpoint: str = "/api/security-events"):
        """이벤트를 큐에 추가합니다."""
        self._enqueue("event", payload, endpoint)

    def enqueue_traffic(self, payload: dict):
        """트래픽 데이터를 큐에 추가합니다."""
        self._enqueue("traffic", payload, "/api/traffic")

    def start(self):
        """백그라운드 플러시 스레드를 시작합니다."""
        if self._running:
            return
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        logger.info(
            "EventQueue flush thread started (interval=%ds, batch=%d)",
            self.flush_interval, self.batch_size,
        )

    def stop(self):
        """플러시 스레드를 중지합니다."""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        # 종료 전 마지막 플러시
        self._flush_batch()
        pending = self._pending_count()
        if pending:
            logger.info("EventQueue stopped with %d events still pending", pending)
        else:
            logger.info("EventQueue stopped — all events flushed")

    def pending_count(self) -> int:
        return self._pending_count()

    # ── 내부 구현 ────────────────────────────────────────────────────────

    def _enqueue(self, kind: str, payload: dict, endpoint: str):
        payload_json = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            # 큐 크기 제한 — 오래된 것부터 삭제
            count = self._pending_count_unlocked()
            if count >= _MAX_QUEUE_SIZE:
                overflow = count - _MAX_QUEUE_SIZE + 1
                self._conn.execute(
                    "DELETE FROM pending_events WHERE id IN "
                    "(SELECT id FROM pending_events ORDER BY id ASC LIMIT ?)",
                    (overflow,),
                )
                logger.warning("EventQueue overflow: dropped %d oldest events", overflow)
            self._conn.execute(
                "INSERT INTO pending_events (kind, payload_json, endpoint, created_at) "
                "VALUES (?, ?, ?, ?)",
                (kind, payload_json, endpoint, time.time()),
            )
            self._conn.commit()

    def _flush_loop(self):
        while self._running:
            time.sleep(self.flush_interval)
            try:
                self._flush_batch()
            except Exception as e:
                logger.error("EventQueue flush error: %s", e)

    def _flush_batch(self):
        """큐에서 batch_size만큼 꺼내 전송을 시도합니다."""
        if not self._send_event_fn or not self._send_traffic_fn:
            return

        with self._lock:
            rows = self._conn.execute(
                "SELECT id, kind, payload_json, endpoint, retry_count "
                "FROM pending_events ORDER BY id ASC LIMIT ?",
                (self.batch_size,),
            ).fetchall()

        if not rows:
            return

        sent_ids = []
        retry_ids = []
        drop_ids = []

        for row_id, kind, payload_json, endpoint, retry_count in rows:
            try:
                payload = json.loads(payload_json)
            except (json.JSONDecodeError, TypeError):
                drop_ids.append(row_id)
                continue

            success = False
            try:
                if kind == "traffic":
                    success = self._send_traffic_fn(payload)
                else:
                    success = self._send_event_fn(payload, endpoint)
            except Exception:
                success = False

            if success:
                sent_ids.append(row_id)
            elif retry_count + 1 >= _MAX_RETRY:
                drop_ids.append(row_id)
                logger.warning("EventQueue: dropping event %d after %d retries", row_id, _MAX_RETRY)
            else:
                retry_ids.append(row_id)

        with self._lock:
            if sent_ids:
                self._conn.execute(
                    f"DELETE FROM pending_events WHERE id IN ({','.join('?' * len(sent_ids))})",
                    sent_ids,
                )
            if drop_ids:
                self._conn.execute(
                    f"DELETE FROM pending_events WHERE id IN ({','.join('?' * len(drop_ids))})",
                    drop_ids,
                )
            if retry_ids:
                self._conn.execute(
                    f"UPDATE pending_events SET retry_count = retry_count + 1 "
                    f"WHERE id IN ({','.join('?' * len(retry_ids))})",
                    retry_ids,
                )
            self._conn.commit()

        if sent_ids:
            logger.info("EventQueue flushed %d events successfully", len(sent_ids))
        if drop_ids:
            logger.warning("EventQueue dropped %d events (max retries)", len(drop_ids))

        # 첫 배치에서 전송 실패 시 이번 라운드 중단 (서버 다운 추정)
        if not sent_ids and retry_ids:
            return

    def _pending_count(self) -> int:
        with self._lock:
            return self._pending_count_unlocked()

    def _pending_count_unlocked(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM pending_events").fetchone()
        return row[0] if row else 0
