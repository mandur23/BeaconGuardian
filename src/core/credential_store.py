"""
config.yaml 비밀번호 난독화 유틸리티.

저장 시: encrypt_password(plain) -> "ENC:xxxxx"
읽기 시: decrypt_password(value) -> plain text

Windows: DPAPI(CryptProtectData) — 현재 사용자만 복호화 가능
기타 OS: Fernet(머신 고유 키 파생) 폴백
"""
import base64
import hashlib
import logging
import os
import platform
import uuid

logger = logging.getLogger(__name__)

_ENC_PREFIX = "ENC:"
_DPAPI_PREFIX = "ENC_DPAPI:"

# ── Windows DPAPI ──────────────────────────────────────────────────────

def _dpapi_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import win32crypt  # noqa: F401
        return True
    except ImportError:
        return False


def _dpapi_encrypt(plaintext: str) -> str:
    import win32crypt
    blob = win32crypt.CryptProtectData(
        plaintext.encode("utf-8"),
        "BeaconGuardian",
        None, None, None, 0,
    )
    return _DPAPI_PREFIX + base64.b64encode(blob).decode("ascii")


def _dpapi_decrypt(token: str) -> str:
    import win32crypt
    blob = base64.b64decode(token[len(_DPAPI_PREFIX):])
    _, data = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
    return data.decode("utf-8")


# ── Fernet 폴백 (Linux / macOS / DPAPI 미설치) ────────────────────────

def _derive_fernet_key() -> bytes:
    """머신 고유값에서 Fernet 키를 파생합니다."""
    try:
        machine_id = str(uuid.getnode())
    except Exception:
        machine_id = "fallback-beacon-guardian"
    salt = b"BeaconGuardian-credential-store"
    dk = hashlib.pbkdf2_hmac("sha256", machine_id.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(dk)


def _fernet_encrypt(plaintext: str) -> str:
    from cryptography.fernet import Fernet
    f = Fernet(_derive_fernet_key())
    token = f.encrypt(plaintext.encode("utf-8"))
    return _ENC_PREFIX + token.decode("ascii")


def _fernet_decrypt(token: str) -> str:
    from cryptography.fernet import Fernet
    f = Fernet(_derive_fernet_key())
    return f.decrypt(token[len(_ENC_PREFIX):].encode("ascii")).decode("utf-8")


# ── 공용 API ──────────────────────────────────────────────────────────

def encrypt_password(plaintext: str) -> str:
    """평문 비밀번호를 난독화된 문자열로 변환합니다."""
    if not plaintext or plaintext.startswith(_ENC_PREFIX) or plaintext.startswith(_DPAPI_PREFIX):
        return plaintext
    if _dpapi_available():
        try:
            return _dpapi_encrypt(plaintext)
        except Exception as e:
            logger.debug("DPAPI encrypt failed, falling back to Fernet: %s", e)
    return _fernet_encrypt(plaintext)


def decrypt_password(value: str) -> str:
    """난독화된 비밀번호를 평문으로 복호화합니다. 평문이면 그대로 반환합니다."""
    if not value:
        return value
    if value.startswith(_DPAPI_PREFIX):
        try:
            return _dpapi_decrypt(value)
        except Exception as e:
            logger.error("DPAPI decrypt failed: %s", e)
            return value
    if value.startswith(_ENC_PREFIX):
        try:
            return _fernet_decrypt(value)
        except Exception as e:
            logger.error("Fernet decrypt failed: %s", e)
            return value
    return value


def is_encrypted(value: str) -> bool:
    """값이 이미 암호화되어 있는지 확인합니다."""
    if not value:
        return False
    return value.startswith(_ENC_PREFIX) or value.startswith(_DPAPI_PREFIX)


encrypt_secret = encrypt_password
decrypt_secret = decrypt_password
