"""desired-state 동기화 스킵 여부 — 단위 테스트용 순수 로직."""


def desired_state_should_skip(local_revision: int, server_revision: int) -> bool:
    """서버 revision 과 로컬이 같으면 전체 reconcile 을 생략해도 됨."""
    return int(server_revision) == int(local_revision)


def desired_state_is_rollback(local_revision: int, server_revision: int) -> bool:
    """서버 revision 이 로컬보다 작으면 롤백·재배포 가능성."""
    return int(server_revision) < int(local_revision)
