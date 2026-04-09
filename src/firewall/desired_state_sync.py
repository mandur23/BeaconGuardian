"""채널 A — 주기적 GET firewall-desired-state 로 WFAS 정합."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from beacon.beacon_client import BeaconClient
    from firewall.local_state_store import LocalStateStore
    from firewall.wfas_applier import WindowsFirewallApplier

from firewall.revision_policy import desired_state_is_rollback, desired_state_should_skip

logger = logging.getLogger(__name__)


class FirewallDesiredStateSync:
    def __init__(
        self,
        client: BeaconClient,
        applier: WindowsFirewallApplier,
        store: LocalStateStore,
        interval_seconds: float = 120.0,
        report_status: bool = False,
    ):
        self.client = client
        self.applier = applier
        self.store = store
        self.interval_seconds = max(30.0, float(interval_seconds))
        self.report_status = report_status
        self._thread: threading.Thread | None = None
        self._running = False
        self._fail_streak = 0

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="FirewallDesiredStateSync", daemon=True)
        self._thread.start()
        logger.info("Firewall desired-state sync started (interval: %ss)", self.interval_seconds)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Firewall desired-state sync stopped")

    def run_once(self) -> bool:
        """시작 시 1회 동기화. 성공 시 True."""
        return self._sync_cycle()

    def _loop(self) -> None:
        while self._running:
            self._sync_cycle()
            delay = float(self.interval_seconds)
            if self._fail_streak > 0:
                delay = min(300.0, self.interval_seconds * (2 ** min(self._fail_streak, 4)))
            end = time.monotonic() + delay
            while self._running and time.monotonic() < end:
                rem = end - time.monotonic()
                if rem <= 0:
                    break
                time.sleep(min(0.5, rem))

    def _sync_cycle(self) -> bool:
        try:
            state = self.store.load()
            last_rev = int(state.get("last_revision", 0))

            snap = self.client.get_firewall_desired_state()
            if snap is None:
                self._fail_streak += 1
                logger.debug("firewall-desired-state: 응답 없음 또는 미구현(404)")
                return False

            rev = int(snap.get("revision", 0))
            if desired_state_should_skip(last_rev, rev):
                self._fail_streak = 0
                logger.debug("firewall revision=%s — 로컬과 동일, 스킵", rev)
                return True
            if desired_state_is_rollback(last_rev, rev):
                logger.warning(
                    "서버 revision(%s) < 로컬(%s) — 롤백/재배포로 간주하고 재정합합니다.",
                    rev,
                    last_rev,
                )

            logger.info("firewall reconcile 시작 (server revision=%s, local=%s)", rev, last_rev)
            result = self.applier.reconcile(snap)
            errors = result.get("errors") or []
            for e in errors:
                logger.warning("WFAS: %s", e)

            # merge_update: 채널 B의 last_command_id 와 경쟁하지 않도록 부분 갱신
            self.store.merge_update(
                {
                    "last_revision": rev,
                    "local_rule_ids": result.get("local_rule_ids") or [],
                }
            )

            if self.report_status:
                lid = result.get("local_rule_ids") or []
                self.client.post_firewall_status(
                    {
                        "lastAppliedRevision": rev,
                        "errors": errors,
                        "localRuleIds": lid,
                    }
                )

            self._fail_streak = 0
            return not errors
        except Exception as e:
            self._fail_streak += 1
            logger.error("firewall sync cycle: %s", e)
            return False
