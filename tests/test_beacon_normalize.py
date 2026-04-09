import pytest

pytest.importorskip("requests")

from beacon import beacon_client as bc


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "LOW"),
        ("high", "HIGH"),
        ("CRITICAL", "CRITICAL"),
        ("custom", "CUSTOM"),
        ("this_is_too_long_for_severity_field", "LOW"),
    ],
)
def test_normalize_severity(raw, expected):
    assert bc._normalize_severity(raw) == expected


def test_normalize_severity_maps_lowercase():
    assert bc._normalize_severity("medium") == "MEDIUM"
