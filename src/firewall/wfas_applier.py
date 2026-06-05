"""Windows 고급 방화벽(WFAS) — BeaconGuardian/ 접두 규칙만 관리."""

from __future__ import annotations

import json
import logging
import platform
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def _display_name(rule_prefix: str, rule_id: int) -> str:
    base = rule_prefix.rstrip("/")
    return f"{base}/{rule_id}"


class WindowsFirewallApplier:
    """
    PowerShell `New-NetFirewallRule` / `Remove-NetFirewallRule` 기반.
    관리자 권한이 없으면 실패할 수 있습니다.
    """

    def __init__(self, rule_name_prefix: str = "BeaconGuardian/"):
        p = rule_name_prefix.strip()
        if not p.endswith("/"):
            p += "/"
        self.rule_prefix = p
        self.logger = logging.getLogger(__name__)

    def is_supported(self) -> bool:
        return platform.system() == "Windows"

    def _run_ps(self, script: str, timeout: int = 120) -> tuple[int, str, str]:
        try:
            r = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return r.returncode, r.stdout or "", r.stderr or ""
        except subprocess.TimeoutExpired as e:
            return -1, "", str(e)
        except Exception as e:
            return -1, "", str(e)

    def list_managed_rule_ids(self) -> tuple[list[int], list[str]]:
        """접두에 맞는 규칙의 서버 ruleId 목록과 오류 메시지."""
        if not self.is_supported():
            return [], ["Windows가 아닙니다."]
        script = rf"""
$prefix = '{self.rule_prefix}'
$ids = New-Object System.Collections.Generic.List[int]
Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object {{
  $dn = $_.DisplayName
  if ($dn -like ($prefix + '*')) {{
    $rest = $dn.Substring($prefix.Length)
    if ($rest -match '^\d+$') {{
      [void]$ids.Add([int]$rest)
    }}
  }}
}}
$ids | Sort-Object -Unique | ConvertTo-Json -Compress
"""
        code, out, err = self._run_ps(script.strip())
        errs = []
        if err.strip():
            errs.append(err.strip())
        if code != 0:
            errs.append(f"exit {code}")
        raw = out.strip()
        if not raw:
            return [], errs
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, int):
                return [parsed], errs
            if isinstance(parsed, list):
                return [int(x) for x in parsed], errs
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            errs.append(f"parse: {e}")
        return [], errs

    def _remove_rule(self, rule_id: int) -> str | None:
        dn = _display_name(self.rule_prefix, rule_id)
        dn_esc = dn.replace("'", "''")
        script = f"Remove-NetFirewallRule -DisplayName '{dn_esc}' -ErrorAction SilentlyContinue"
        code, _, err = self._run_ps(script, timeout=60)
        if code != 0 and err.strip():
            return err.strip()
        return None

    def _upsert_rule(self, rule: dict[str, Any]) -> str | None:
        rid = int(rule["ruleId"])
        dn = _display_name(self.rule_prefix, rid)
        dn_esc = dn.replace("'", "''")

        action = str(rule.get("action") or "block").lower()
        ps_action = "Block" if action in ("block", "deny") else "Allow"

        direction = str(rule.get("direction") or "outbound").lower()
        ps_dir = "Outbound" if direction == "outbound" else "Inbound"

        addrs = rule.get("remoteAddresses") or rule.get("remoteAddress")
        if isinstance(addrs, str):
            addrs = [addrs]
        if not isinstance(addrs, list):
            addrs = []
        addrs = [str(a).strip() for a in addrs if str(a).strip()]
        if not addrs:
            return "remoteAddresses 비어 있음"

        for a in addrs:
            if not re.match(r"^[A-Za-z0-9:.\-_/%]+$", a):
                return f"허용되지 않는 주소 형식: {a!r}"

        addr_parts = ",".join("'" + x.replace("'", "''") + "'" for x in addrs)
        en = "True" if bool(rule.get("enabled", True)) else "False"
        profile = str(rule.get("profile") or "Any").strip() or "Any"
        profile_esc = profile.replace("'", "''")

        desc = str(rule.get("displayName") or "").replace("'", "''")[:256]
        proto_extra = self._protocol_port_ps_fragment(rule)

        script = f"""
$dn = '{dn_esc}'
Remove-NetFirewallRule -DisplayName $dn -ErrorAction SilentlyContinue
$ra = @({addr_parts})
New-NetFirewallRule -DisplayName $dn -Direction {ps_dir} -Action {ps_action} -RemoteAddress $ra -Profile '{profile_esc}' -Enabled {en}{proto_extra} -ErrorAction Stop
"""
        if desc:
            script += (
                f"try {{ Set-NetFirewallRule -DisplayName $dn -Description '{desc}' "
                f"-ErrorAction SilentlyContinue }} catch {{ }}\n"
            )

        code, out, err = self._run_ps(script.strip(), timeout=90)
        if code != 0:
            msg = (err or out or "").strip() or f"exit {code}"
            return msg
        return None

    def _protocol_port_ps_fragment(self, rule: dict[str, Any]) -> str:
        """New-NetFirewallRule 에 붙일 프로토콜·포트 인자(앞에 공백 포함). ICMP 계열은 포트 생략."""
        proto = str(rule.get("protocol") or "any").lower().strip()
        bits: list[str] = []

        if proto not in ("", "any", "*", "all"):
            if proto in ("tcp", "6"):
                bits.append("-Protocol TCP")
            elif proto in ("udp", "17"):
                bits.append("-Protocol UDP")
            elif proto in ("icmpv4", "icmp"):
                bits.append("-Protocol ICMPv4")
            elif proto == "icmpv6":
                bits.append("-Protocol ICMPv6")
            elif proto.isdigit():
                bits.append(f"-Protocol {proto}")
            else:
                bits.append(f"-Protocol {proto.upper()}")

        proto_joined = " ".join(bits)
        is_icmp = "ICMP" in proto_joined

        if not is_icmp:
            lp = rule.get("localPort")
            rp = rule.get("remotePort")
            if lp not in (None, "", "*"):
                try:
                    bits.append(f"-LocalPort {int(lp)}")
                except (TypeError, ValueError):
                    bits.append(f"-LocalPort {lp}")
            if rp not in (None, "", "*"):
                try:
                    bits.append(f"-RemotePort {int(rp)}")
                except (TypeError, ValueError):
                    bits.append(f"-RemotePort {rp}")

        if not bits:
            return ""
        return " " + " ".join(bits)

    def apply_b_command(self, cmd: dict[str, Any]) -> list[str]:
        """
        채널 B 단일 명령. 오류 메시지 목록 반환(빈 목록이면 성공).
        action: UPSERT_RULE | DELETE_RULE | ENABLE_PROFILE | NOOP
        """
        action = str(cmd.get("action") or "NOOP").strip().upper().replace(" ", "_")
        if action in ("NOOP", ""):
            return []

        payload = cmd.get("payload")
        if not isinstance(payload, dict):
            payload = {}

        if action == "DELETE_RULE":
            rid = payload.get("ruleId")
            if rid is None:
                return ["DELETE_RULE: ruleId 없음"]
            try:
                rid_i = int(rid)
            except (TypeError, ValueError):
                return [f"DELETE_RULE: 잘못된 ruleId {rid!r}"]
            err = self._remove_rule(rid_i)
            return [err] if err else []

        if action == "UPSERT_RULE":
            if "ruleId" not in payload and isinstance(payload.get("rule"), dict):
                payload = payload["rule"]
            if "ruleId" not in payload:
                return ["UPSERT_RULE: ruleId 없음"]
            err = self._upsert_rule(payload)
            return [err] if err else []

        if action == "ENABLE_PROFILE":
            fp = payload.get("firewallProfiles")
            if fp is None and isinstance(payload, dict):
                fp = {
                    k: v
                    for k, v in payload.items()
                    if k in ("domain", "private", "public")
                }
            if not isinstance(fp, dict) or not fp:
                return ["ENABLE_PROFILE: firewallProfiles 없음"]
            e = self._apply_profiles(fp)
            return [e] if e else []

        return [f"알 수 없는 action: {action}"]

    def reconcile(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        """
        서버 스냅샷 전체를 기준으로 접두 규칙 집합을 맞춥니다.
        반환: { \"errors\": [...], \"local_rule_ids\": [...] }
        """
        errors: list[str] = []
        rules = snapshot.get("rules") or []
        if not isinstance(rules, list):
            rules = []

        desired_ids = set()
        parsed: list[dict[str, Any]] = []
        for r in rules:
            if not isinstance(r, dict) or "ruleId" not in r:
                continue
            try:
                rid = int(r["ruleId"])
            except (TypeError, ValueError):
                errors.append(f"잘못된 ruleId: {r!r}")
                continue
            desired_ids.add(rid)
            parsed.append(r)

        if not self.is_supported():
            return {"errors": ["Windows 방화벽 미지원"], "local_rule_ids": []}

        current, list_errs = self.list_managed_rule_ids()
        for e in list_errs:
            errors.append(e)

        to_remove = set(current) - desired_ids
        for rid in sorted(to_remove):
            err = self._remove_rule(rid)
            if err:
                errors.append(f"remove {rid}: {err}")

        for r in parsed:
            err = self._upsert_rule(r)
            if err:
                errors.append(f"upsert {r.get('ruleId')}: {err}")

        # 프로필 (선택)
        profiles = snapshot.get("firewallProfiles")
        if isinstance(profiles, dict):
            prof_err = self._apply_profiles(profiles)
            if prof_err:
                errors.append(prof_err)

        final, _ = self.list_managed_rule_ids()
        return {"errors": errors, "local_rule_ids": [str(x) for x in sorted(final)]}

    def _apply_profiles(self, profiles: dict[str, Any]) -> str | None:
        """domain/private/public → on/off. 실패 시 메시지."""
        mapping = {
            "domain": "Domain",
            "private": "Private",
            "public": "Public",
        }
        parts = []
        for key, prof in mapping.items():
            if key not in profiles:
                continue
            val = str(profiles[key]).lower()
            enabled = val in ("on", "true", "1", "enabled")
            st = "Enabled" if enabled else "Disabled"
            parts.append(f"Set-NetFirewallProfile -Profile {prof} -Enabled {st} -ErrorAction SilentlyContinue")
        if not parts:
            return None
        script = "\n".join(parts)
        code, _, err = self._run_ps(script, timeout=60)
        if code != 0 and err.strip():
            return f"firewallProfiles: {err.strip()}"
        return None
