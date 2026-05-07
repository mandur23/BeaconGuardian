"""채널 B — 롱폴로 firewall-commands 수신 후 즉시 WFAS 적용. A가 최종 정합."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from beacon.beacon_client import BeaconClient
    from firewall.local_state_store import LocalStateStore
    from firewall.wfas_applier import WindowsFirewallApplier

logger = logging.getLogger(__name__)


class FirewallCommandReceiver:
    """
    GET /api/agents/me/firewall-commands?agentName=…&since=… (롱폴).
    응답 `FirewallCommandsPollResponse` 형태: `commands`, `lastCommandId`.
    """

    def __init__(
        self,
        client: BeaconClient,
        applier: WindowsFirewallApplier,
        store: LocalStateStore,
        *,
        long_poll_timeout: float = 75.0,
        channel_b_enabled: bool = True,
        endpoint_missing_backoff: float = 30.0,
    ):
        self.client = client
        self.applier = applier
        self.store = store
        self.long_poll_timeout = max(15.0, float(long_poll_timeout))
        self.channel_b_enabled = channel_b_enabled
        self.endpoint_missing_backoff = max(5.0, float(endpoint_missing_backoff))
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        if not self.channel_b_enabled or not self.applier.is_supported():
            logger.info(
                "FirewallCommandReceiver: 비활성(channel_b=%s, windows=%s)",
                self.channel_b_enabled,
                self.applier.is_supported(),
            )
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="FirewallCommandReceiver", daemon=True
        )
        self._thread.start()
        logger.info(
            "FirewallCommandReceiver 시작 (롱폴 %.0fs, agentName=%s)",
            self.long_poll_timeout,
            self.client.agent_name,
        )

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=min(self.long_poll_timeout + 10.0, 120.0))
            self._thread = None
        logger.info("FirewallCommandReceiver 정지")

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while self._running and time.monotonic() < end:
            rem = end - time.monotonic()
            if rem <= 0:
                break
            time.sleep(min(0.5, rem))

    def _loop(self) -> None:
        err_streak = 0
        while self._running:
            try:
                st = self.store.load()
                since = (st.get("last_command_id") or "").strip() or None

                data = self.client.fetch_firewall_commands(
                    since_cursor=since,
                    long_poll_timeout=self.long_poll_timeout,
                )
                if data is None:
                    logger.debug(
                        "firewall-commands 응답 없음(404/오류) — %ss 후 재시도",
                        self.endpoint_missing_backoff,
                    )
                    self._sleep(self.endpoint_missing_backoff)
                    err_streak += 1
                    continue

                err_streak = 0
                commands = data.get("commands")
                if not isinstance(commands, list):
                    commands = []

                last_cid = data.get("lastCommandId")
                if last_cid is not None:
                    last_cid = str(last_cid).strip()

                for cmd in commands:
                    if not isinstance(cmd, dict):
                        continue
                    cid = cmd.get("commandId", "?")
                    action = cmd.get("action")

                    # [NEW] 프로세스 원격 종료(Kill Switch) 처리
                    if action == "KILL_PROCESS":
                        try:
                            import psutil
                            import json
                            payload = json.loads(cmd.get("payload", "{}"))
                            pid = payload.get("pid")
                            if pid:
                                proc = psutil.Process(pid)
                                proc.terminate() # 또는 kill()
                                logger.warning("🛡️ 원격 킬 스위치 작동: PID %s 종료됨 (Action: %s)", pid, action)
                            continue 
                        except Exception as kill_err:
                            logger.error("B 명령(KILL_PROCESS) 실행 실패: %s", kill_err)
                            continue

                    errs = self.applier.apply_b_command(cmd)
                    if errs:
                        for e in errs:
                            logger.warning("B 명령 실패 commandId=%s: %s", cid, e)
                    else:
                        logger.info(
                            "B 명령 적용 commandId=%s action=%s",
                            cid,
                            action,
                        )

                if last_cid:
                    self.store.merge_update({"last_command_id": last_cid})
                elif commands:
                    last = commands[-1]
                    if isinstance(last, dict) and last.get("commandId"):
                        self.store.merge_update(
                            {"last_command_id": str(last["commandId"])}
                        )

                if not commands:
                    self._sleep(0.25)

            except Exception as e:
                err_streak += 1
                logger.error("FirewallCommandReceiver 루프: %s", e)
                self._sleep(min(60.0, 2.0 ** min(err_streak, 5)))
