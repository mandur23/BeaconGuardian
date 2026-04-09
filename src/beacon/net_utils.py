"""로컬 IP 선택 — 서버로 나가는 경로와 맞추기(UDP 소켓 트릭). IPv4 우선, 없으면 IPv6."""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _is_loopback_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return ip_str.startswith("127.")


def get_ipv4_via_hostname():
    """호스트명만으로 얻는 IPv4 (다중 NIC에서 부정확할 수 있음)."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def get_local_ipv4_towards_server(server_url: str) -> str:
    """
    Beacon 서버로 실제 나갈 때 쓰이는 로컬 IP를 추정합니다(IPv4 우선, IPv6 전용 호스트면 IPv6).
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
        addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfos:
            return get_ipv4_via_hostname()
        v4_first = [ai for ai in addrinfos if ai[0] == socket.AF_INET]
        v6_rest = [ai for ai in addrinfos if ai[0] == socket.AF_INET6]
        ordered = v4_first + v6_rest
        for _family, _type, _proto, _canon, sockaddr in ordered:
            af = _family
            try:
                s = socket.socket(af, socket.SOCK_DGRAM)
                try:
                    s.connect(sockaddr)
                    local = s.getsockname()[0]
                    if local and not _is_loopback_ip(local):
                        return local
                except OSError as e:
                    logger.debug("UDP route trick failed (%s): %s", af, e)
                finally:
                    s.close()
            except OSError as e:
                logger.debug("socket create failed (%s): %s", af, e)
    except Exception as e:
        logger.debug("get_local_ipv4_towards_server: %s", e)
    return get_ipv4_via_hostname()


def get_ipv4_for_agent(server_url: str, strategy: str = "outbound") -> str:
    """
    strategy:
      - outbound: 서버 방향 라우트에 맞는 로컬 주소(IPv4 우선, IPv6 전용 서버면 IPv6)
      - hostname: 기존 방식 (gethostbyname(hostname), IPv4)
    """
    import os
    # 도커/테스트 환경에서 해외 위치 시뮬레이션을 위한 가짜 IP 주소 지원
    mock_ip = os.environ.get("BEACON_MOCK_IP")
    if mock_ip:
        if mock_ip.upper() == "RANDOM":
            import random
            overseas_ips = [
                "8.8.8.8",         # US (Google)
                "210.140.131.199", # JP (Mixi)
                "212.58.244.70",   # UK (BBC)
                "193.159.160.1",   # DE (DT)
                "111.90.150.1",    # SG
                "1.1.1.1",         # AU (Cloudflare)
                "202.160.128.10"   # HK
            ]
            return random.choice(overseas_ips)
        return mock_ip

    if (strategy or "outbound").lower() == "hostname":
        return get_ipv4_via_hostname()
    return get_local_ipv4_towards_server(server_url)


def is_private_ipv4(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False
