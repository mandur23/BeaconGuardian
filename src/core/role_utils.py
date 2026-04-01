"""로그인 응답·로컬 화이트리스트로 admin | user 결정."""

from __future__ import annotations


def _norm_list(names: list | None) -> set[str]:
    if not names:
        return set()
    return {str(x).strip().lower() for x in names if str(x).strip()}


def resolve_role_from_login_response(
    data: dict | None,
    username: str,
    admin_usernames: list[str] | None = None,
) -> str:
    """
    우선순위:
    1) 응답 JSON의 role / userRole (문자열)
    2) 로컬 admin_usernames(Windows 사용자명 등)에 username이 포함되면 admin
    3) 그 외 user
    """
    if data:
        raw = data.get("role") if isinstance(data, dict) else None
        if raw is None and isinstance(data, dict):
            raw = data.get("userRole")
        if raw is not None:
            s = str(raw).strip().lower()
            if s in ("admin", "administrator", "관리자", "true", "1"):
                return "admin"
            if s in ("user", "member", "false", "0"):
                return "user"

    if username and username.strip().lower() in _norm_list(admin_usernames):
        return "admin"
    return "user"
