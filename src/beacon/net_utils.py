"""로컬 IPv4 선택 — 서버로 나가는 경로와 맞추기(UDP 소켓 트릭)."""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_ipv4_via_hostname():
    """호스트명만으로 얻는 IPv4 (다중 NIC에서 부정확할 수 있음)."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def get_local_ipv4_towards_server(server_url: str) -> str:
    """
    Beacon 서버로 실제 나갈 때 쓰이는 로컬 IPv4를 추정합니다.
    UDP connect는 패킷을 보내지 않고 라우팅만 결정합니다.
    """
    try:
        parsed = urlparse(server_url)
        host = parsed.hostname
        if not host:
            return get_ipv4_via_hostname()
        port = parsed.port
        if port is None:
            port = 443 if (parsed.scheme or "").lower() == "https" else 80
        addrinfos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addrinfos:
            return get_ipv4_via_hostname()
        target = addrinfos[0][4]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(target)
            local = s.getsockname()[0]
            if local and not local.startswith("127."):
                return local
        except OSError as e:
            logger.debug("UDP route trick failed: %s", e)
        finally:
            s.close()
    except Exception as e:
        logger.debug("get_local_ipv4_towards_server: %s", e)
    return get_ipv4_via_hostname()


def get_ipv4_for_agent(server_url: str, strategy: str = "outbound") -> str:
    """
    strategy:
      - outbound: 서버 방향 라우트에 맞는 로컬 IP (권장, 집계 일치에 유리)
      - hostname: 기존 방식 (gethostbyname(hostname))
    """
    if (strategy or "outbound").lower() == "hostname":
        return get_ipv4_via_hostname()
    return get_local_ipv4_towards_server(server_url)


def is_private_ipv4(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False
