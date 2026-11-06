import pytest

from depaudit_mcp import severity as sev
from depaudit_mcp import versions as ver


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.0", "1.0.0", 0),
        ("1.9", "1.10", -1),
        ("2.19.1", "2.20.0", -1),
        ("1.0.0rc1", "1.0.0", -1),
        ("1.0.0-beta.2", "1.0.0-beta.10", -1),
        ("1.0.0", "1.0.0.post1", -1),
        ("v1.6.3", "1.7.7", -1),
        ("0.0.8", "0.2.4", -1),
        ("2026.10.23", "2026.9.1", 1),
        ("1!2.0", "2.0", 0),
    ],
)
def test_compare(a, b, expected):
    assert ver.compare(a, b) == expected


def test_unparseable_versions_compare_as_none():
    assert ver.compare("deadbeef", "1.0") is None
    assert ver.parse("latest") is None


def test_bump_kind_and_breaking():
    assert ver.bump_kind("2.19.1", "2.20.0") == "minor"
    assert ver.bump_kind("2.19.1", "3.0.0") == "major"
    assert ver.bump_kind("2.19.1", "2.19.2") == "patch"
    assert ver.bump_kind("2.19.1", "2.19.1") is None
    assert ver.bump_kind("2.19.1", "2.0.0") is None
    assert ver.is_breaking("1.23", "2.0")
    assert ver.is_breaking("0.0.8", "0.2.4")  # 0.x minor bump may break
    assert not ver.is_breaking("4.17.15", "4.17.21")
    assert not ver.is_breaking("2.19.1", "2.20.0")


def test_prerelease_detection():
    assert ver.is_prerelease("2.0.0rc1") and not ver.is_prerelease("2.0.0")


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # GHSA-x84v-xcm2-53pg
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # classic reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_scores(vector, score):
    assert sev.cvss3_score(vector) == score


def test_bucket_boundaries():
    got = [sev.bucket(x) for x in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0)]
    assert got == ["CRITICAL", "HIGH", "HIGH", "MODERATE", "MODERATE", "LOW", "LOW", "UNKNOWN"]


def test_of_record_prefers_vector_then_label():
    rec = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert sev.of_record(rec) == ("CRITICAL", 9.8)
    assert sev.of_record({"database_specific": {"severity": "MEDIUM"}}) == ("MODERATE", None)
    assert sev.of_record({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}) == ("UNKNOWN", None)
    assert sev.of_record({}) == ("UNKNOWN", None)
