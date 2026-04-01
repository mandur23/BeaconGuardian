"""앱 전역 컨텍스트 — UI/트레이에서 참조하는 단일 진실(role 등)."""


class AppContext:
    _role: str | None = None

    @classmethod
    def set_role(cls, role: str) -> None:
        r = (role or "user").strip().lower()
        cls._role = "admin" if r in ("admin", "administrator", "관리자") else "user"

    @classmethod
    def get_role(cls) -> str | None:
        return cls._role

    @classmethod
    def is_admin(cls) -> bool:
        return cls._role == "admin"
