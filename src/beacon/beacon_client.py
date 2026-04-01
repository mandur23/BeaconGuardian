import base64
import json
import logging
import platform
import re
import socket
import threading
import time
import getpass

import requests

from core.credential_store import decrypt_password
from core.role_utils import resolve_role_from_login_response
from beacon.net_utils import get_ipv4_for_agent
from beacon.tls_adapter import apply_spki_mount

def _parse_jwt_exp(token):
    """JWT 페이로드의 exp(초)만 디코드. 서명 검증 없음."""
    if not token or "." not in token:
        return None
    try:
        payload_b64 = token.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        if pad != 4:
            payload_b64 += "=" * pad
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = data.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


def _normalize_severity(value):
    if value is None:
        return "LOW"
    s = str(value).strip().upper()
    allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO", "WARNING", "ERROR"}
    if s in allowed:
        return s
    low = str(value).strip().lower()
    m = {
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
        "info": "INFO",
        "warning": "WARNING",
        "error": "ERROR",
    }
    return m.get(low, s if len(s) <= 12 else "LOW")


class BeaconClient:
    def __init__(
        self,
        server_url,
        username,
        password,
        agent_name="BeaconGuardian",
        agent_version="1.0.0",
        heartbeat_interval_seconds=60,
        tls=None,
        ip_selection="outbound",
        jwt_refresh_before_exp_seconds=90,
        admin_usernames=None,
    ):
        tls = tls or {}
        self.server_url = server_url.rstrip("/")
        self.username = username
        self.password = decrypt_password(password)
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.token = None
        self._token_exp = None
        self.logger = logging.getLogger("BeaconClient")
        self.ip_selection = ip_selection or "outbound"
        self.jwt_refresh_before_exp_seconds = max(30, int(jwt_refresh_before_exp_seconds))

        self._require_https = bool(tls.get("require_https", False))
        if self._require_https and not self.server_url.lower().startswith("https://"):
            raise ValueError(
                "beacon.tls.require_https 가 켜져 있으면 server_url 은 https:// 로 지정해야 합니다."
            )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"{agent_name}/{agent_version}"})
        self._configure_tls(tls)

        self.last_login = 0
        self.login_timeout = 600

        try:
            h = int(heartbeat_interval_seconds)
        except (TypeError, ValueError):
            h = 60
        self.heartbeat_interval = max(10, min(299, h))
        self.heartbeat_thread = None
        self.heartbeat_running = False

        self.system_info = self._collect_system_info()
        self._admin_usernames = list(admin_usernames or [])
        self.role = "user"

    @staticmethod
    def _sanitize_response_text(text, max_len=240):
        """응답 본문에서 민감 키를 마스킹하고 길이를 제한합니다."""
        if not text:
            return ""
        t = str(text).replace("\r", " ").replace("\n", " ").strip()
        if len(t) > max_len:
            t = t[:max_len] + "...(truncated)"
        # token/password/authorization/secret 계열 키 값 마스킹
        t = re.sub(
            r'(?i)\b(token|password|authorization|secret)\b\s*[:=]\s*["\']?[^,"\'}\s]+',
            r"\1=<redacted>",
            t,
        )
        return t

    def _log_http_error(self, prefix, response):
        body = self._sanitize_response_text(getattr(response, "text", ""))
        if body:
            self.logger.error("%s: %s - %s", prefix, response.status_code, body)
        else:
            self.logger.error("%s: %s", prefix, response.status_code)

    def _configure_tls(self, tls):
        ca = tls.get("ca_bundle")
        if ca:
            self.session.verify = ca
        else:
            self.session.verify = True

        c_cert = tls.get("client_cert")
        c_key = tls.get("client_key")
        if c_cert and c_key:
            self.session.cert = (c_cert, c_key)
        elif c_cert:
            self.session.cert = c_cert

        pins = tls.get("pin_spki_sha256") or tls.get("pin_spki")
        if pins:
            if isinstance(pins, str):
                pins = [pins]
            apply_spki_mount(self.session, pins)

    def _collect_system_info(self):
        try:
            ip_addr = get_ipv4_for_agent(self.server_url, self.ip_selection)
            return {
                "hostname": socket.gethostname(),
                "ipAddress": ip_addr,
                "osType": platform.system(),
                "osVersion": platform.version(),
                "username": getpass.getuser(),
                "agentName": self.agent_name,
                "agentVersion": self.agent_version,
            }
        except Exception as e:
            self.logger.error("Failed to collect system info: %s", e)
            return {
                "hostname": "unknown",
                "ipAddress": "0.0.0.0",
                "osType": "unknown",
                "osVersion": "unknown",
                "username": "unknown",
                "agentName": self.agent_name,
                "agentVersion": self.agent_version,
            }

    def _set_token(self, token):
        self.token = token
        self._token_exp = _parse_jwt_exp(token) if token else None

    def _ensure_token_fresh(self):
        """만료 전에 선제 재로그인."""
        if not self.token:
            return
        if self._token_exp is None:
            return
        now = time.time()
        if now >= self._token_exp - self.jwt_refresh_before_exp_seconds:
            self.logger.info("JWT 만료 임박 — 재인증합니다.")
            self._set_token(None)
            if self._authenticate():
                self._register_agent()

    def login(self):
        if not self._authenticate():
            return False
        if not self._register_agent():
            self.logger.warning("Agent registration failed, but will continue with auth token")
        self._start_heartbeat()
        return True

    def _authenticate(self):
        url = f"{self.server_url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        try:
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                tok = data.get("token")
                self._set_token(tok)
                self.role = resolve_role_from_login_response(
                    data,
                    self.username,
                    self._admin_usernames,
                )
                self.logger.info("Successfully authenticated with Beacon server.")
                self.last_login = time.time()
                return True
            self._log_http_error("Login failed", response)
        except Exception as e:
            self.logger.error("Error during login: %s", e)
        return False

    def _register_agent(self):
        url = f"{self.server_url}/api/agents/register"
        payload = {
            "agentName": self.system_info["agentName"],
            "hostname": self.system_info["hostname"],
            "ipAddress": self.system_info["ipAddress"],
            "osType": self.system_info["osType"],
            "osVersion": self.system_info["osVersion"],
            "agentVersion": self.system_info["agentVersion"],
            "username": self.system_info["username"],
            "metadata": json.dumps({"platform": platform.platform()}),
        }
        try:
            response = self.session.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    self.logger.info(
                        "Agent registered: %s (ID: %s)",
                        data.get("agentName"),
                        data.get("agentId"),
                    )
                    return True
            self._log_http_error("Agent registration failed", response)
        except Exception as e:
            self.logger.error("Error during agent registration: %s", e)
        return False

    def _send_heartbeat(self):
        url = f"{self.server_url}/api/agents/heartbeat"
        payload = {"agentName": self.agent_name}
        try:
            response = self.session.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if response.status_code == 200:
                self.logger.debug("Heartbeat sent successfully")
                return True
            self.logger.warning("Heartbeat failed: %s", response.status_code)
        except Exception as e:
            self.logger.debug("Heartbeat error: %s", e)
        return False

    def _start_heartbeat(self):
        if self.heartbeat_running:
            return
        if self.token:
            self._send_heartbeat()
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        self.logger.info("Heartbeat thread started (interval: %ss)", self.heartbeat_interval)

    def disconnect(self):
        if not self.token:
            return False
        url = f"{self.server_url}/api/agents/disconnect"
        payload = {"agentName": self.agent_name}
        try:
            response = self.session.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if response.status_code == 200:
                self.logger.info("Disconnect notified to server.")
                return True
            body = self._sanitize_response_text(response.text)
            if body:
                self.logger.warning("Disconnect failed: %s - %s", response.status_code, body)
            else:
                self.logger.warning("Disconnect failed: %s", response.status_code)
        except Exception as e:
            self.logger.debug("Disconnect error: %s", e)
        return False

    def _heartbeat_loop(self):
        while self.heartbeat_running:
            time.sleep(self.heartbeat_interval)
            self._ensure_token_fresh()
            if not self._send_heartbeat():
                if not self.token or (time.time() - self.last_login) > self.login_timeout:
                    self.logger.info("Re-authenticating due to heartbeat failure")
                    self._authenticate()

    def stop_heartbeat(self):
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
        self.logger.info("Heartbeat thread stopped")

    def clear_credentials(self):
        """종료 시 메모리에서 민감 정보 참조를 제거합니다."""
        self._set_token(None)
        self.password = ""
        self.session.headers.pop("Authorization", None)
        self.session.close()

    def _get_headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _json_string_field(name, value):
        """Spring `SecurityEvent`에서 String으로 매핑되는 필드(metadata 등)용."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)

    def _normalize_event(self, event_data):
        normalized = dict(event_data)
        if "severity" in normalized:
            normalized["severity"] = _normalize_severity(normalized["severity"])
        # 서버(Jackson)는 metadata를 JSON 문자열 필드로 기대 — dict/list 등은 반드시 직렬화
        if "metadata" in normalized:
            normalized["metadata"] = self._json_string_field("metadata", normalized["metadata"])
        if "rawData" in normalized and normalized["rawData"] is not None:
            if not isinstance(normalized["rawData"], str):
                normalized["rawData"] = self._json_string_field("rawData", normalized["rawData"])

        normalized.setdefault("sourceIp", self.system_info.get("ipAddress", "127.0.0.1"))
        normalized.setdefault("protocol", "UNKNOWN")
        normalized.setdefault("port", 0)
        # 차단 여부는 Beacon 웹의 이벤트 차단 정책에서만 결정 — 에이전트는 탐지 정보만 전송
        normalized.pop("blocked", None)
        rs = normalized.setdefault("riskScore", 0.0)
        try:
            normalized["riskScore"] = float(rs)
        except (TypeError, ValueError):
            normalized["riskScore"] = 0.0
        return normalized

    def _normalize_traffic(self, traffic_data):
        t = dict(traffic_data)
        t.setdefault("sourceIp", self.system_info.get("ipAddress", "127.0.0.1"))
        if "rawData" in t and t["rawData"] is not None and not isinstance(t["rawData"], str):
            t["rawData"] = self._json_string_field("rawData", t["rawData"])
        return t

    def send_event(self, event_data, endpoint="/api/security-events"):
        url = f"{self.server_url}{endpoint}"
        max_retries = 3
        payload = self._normalize_event(event_data)

        for attempt in range(max_retries):
            try:
                self._ensure_token_fresh()
                if not self.token:
                    if not self._authenticate():
                        time.sleep(2**attempt)
                        continue

                response = self.session.post(
                    url, json=payload, headers=self._get_headers(), timeout=10
                )

                if response.status_code in (200, 201):
                    self.logger.debug("Data successfully sent to %s", endpoint)
                    return True
                if response.status_code == 401:
                    self.logger.warning("Token expired or invalid, attempting re-login.")
                    self._set_token(None)
                    if self._authenticate():
                        continue
                body = self._sanitize_response_text(response.text)
                if body:
                    self.logger.error("Failed to send data to %s: %s - %s", endpoint, response.status_code, body)
                else:
                    self.logger.error("Failed to send data to %s: %s", endpoint, response.status_code)
            except Exception as e:
                self.logger.error(
                    "Error sending data (attempt %s/%s) to %s: %s",
                    attempt + 1,
                    max_retries,
                    endpoint,
                    e,
                )
            time.sleep(2**attempt)
        return False

    def send_traffic(self, traffic_data):
        url = f"{self.server_url}/api/traffic"
        max_retries = 3
        payload = self._normalize_traffic(traffic_data)

        for attempt in range(max_retries):
            try:
                self._ensure_token_fresh()
                if not self.token:
                    if not self._authenticate():
                        time.sleep(2**attempt)
                        continue
                response = self.session.post(
                    url, json=payload, headers=self._get_headers(), timeout=10
                )
                if response.status_code in (200, 201):
                    return True
                if response.status_code == 401:
                    self._set_token(None)
                    if self._authenticate():
                        continue
                body = self._sanitize_response_text(response.text)
                if body:
                    self.logger.error("Failed to send traffic: %s - %s", response.status_code, body)
                else:
                    self.logger.error("Failed to send traffic: %s", response.status_code)
            except Exception as e:
                self.logger.error("send_traffic error: %s", e)
            time.sleep(2**attempt)
        return False
