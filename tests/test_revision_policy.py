from firewall.revision_policy import (
    desired_state_is_rollback,
    desired_state_should_skip,
)


def test_skip_when_equal():
    assert desired_state_should_skip(10, 10) is True
    assert desired_state_should_skip(0, 0) is True


def test_no_skip_when_forward():
    assert desired_state_should_skip(10, 11) is False


def test_rollback_detection():
    assert desired_state_is_rollback(10, 9) is True
    assert desired_state_is_rollback(10, 10) is False
    assert desired_state_is_rollback(10, 11) is False
