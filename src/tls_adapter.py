"""HTTPS: SPKI 핀닝(선택), urllib3 PoolManager 연동."""
import hashlib
import logging
from typing import List, Optional

from urllib3 import PoolManager
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import SSLError as Urllib3SSLError
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

_SPKI_IMPORT_ERROR = None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError as e:
    x509 = None  # type: ignore
    _SPKI_IMPORT_ERROR = e


def spki_sha256_hex_from_der_cert(cert_der: bytes) -> str:
    """DER 인증서에서 SubjectPublicKeyInfo(SPKI)의 SHA256(hex)."""
    if x509 is None:
        raise RuntimeError(
            "SPKI pinning requires 'cryptography' package: pip install cryptography"
        ) from _SPKI_IMPORT_ERROR
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _normalize_pin(p: str) -> str:
    return p.lower().replace(":", "").replace(" ", "")


class SPKIHTTPSConnectionPool(HTTPSConnectionPool):
    """연결 후 SPKI 해시가 허용 목록에 있는지 검사."""

    def __init__(self, *args, **kwargs):
        self._spki_pins = _normalize_pin_list(kwargs.pop("spki_pins", None))
        super().__init__(*args, **kwargs)

    def _validate_conn(self, conn):
        super()._validate_conn(conn)
        if not self._spki_pins:
            return
        sock = getattr(conn, "sock", None)
        if sock is None:
            raise Urllib3SSLError("SPKI pinning: no socket")
        cert_der = sock.getpeercert(binary_form=True)
        if not cert_der:
            raise Urllib3SSLError("SPKI pinning: no peer certificate (binary)")
        got = spki_sha256_hex_from_der_cert(cert_der)
        if got.lower() not in self._spki_pins:
            logger.error("SPKI pin mismatch (got %s...)", got[:16])
            raise Urllib3SSLError("Certificate SPKI pin mismatch")
        logger.debug("SPKI pin OK")


def _normalize_pin_list(pins: Optional[List[str]]) -> set:
    if not pins:
        return set()
    return {_normalize_pin(p) for p in pins if p}


class SPKIPoolManager(PoolManager):
    pool_classes_by_scheme = {
        "http": HTTPConnectionPool,
        "https": SPKIHTTPSConnectionPool,
    }


class SPKIHTTPAdapter(HTTPAdapter):
    def __init__(self, spki_pins: Optional[List[str]] = None, **kwargs):
        self._spki_pins = spki_pins or []
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs = dict(pool_kwargs)
        pool_kwargs["spki_pins"] = self._spki_pins
        self.poolmanager = SPKIPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def apply_spki_mount(session, spki_pins: Optional[List[str]]) -> None:
    """세션에 https:// SPKI 어댑터를 장착합니다. pins가 비면 아무 것도 하지 않습니다."""
    if not spki_pins:
        return
    if x509 is None:
        raise RuntimeError(
            "SPKI pinning requires 'cryptography': pip install cryptography"
        ) from _SPKI_IMPORT_ERROR
    session.mount("https://", SPKIHTTPAdapter(spki_pins=list(spki_pins)))
