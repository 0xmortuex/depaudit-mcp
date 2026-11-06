"""The real HTTP client and OSV/registry clients against a local server replaying recorded data."""

import pytest

from depaudit_mcp import osv as osv_mod
from depaudit_mcp.errors import NetworkError, NotFoundError, RateLimitError
from depaudit_mcp.http import Http
from depaudit_mcp.model import NPM, PYPI, Pkg
from depaudit_mcp.osv import OSV
from depaudit_mcp.registry import Registry

REQ = Pkg(PYPI, "requests", "2.19.1")
CLEAN = Pkg(PYPI, "certifi", "2026.10.23")


def client(fake, **kw):
    return OSV(Http(sleep=lambda s: None, **kw), base=fake.url)


def test_batch_returns_ids_per_package(fake):
    out = client(fake).vuln_ids([REQ, CLEAN])
    assert "GHSA-x84v-xcm2-53pg" in out[REQ]
    assert out[CLEAN] == []
    assert fake.unrecorded == []


def test_pagination_follows_next_page_token(fake):
    full = client(fake).vuln_ids([REQ])[REQ]
    assert len(full) >= 3
    fake.page_size = 1
    fake.calls.clear()
    paged = client(fake).vuln_ids([REQ])[REQ]
    assert paged == full
    assert len([c for c in fake.calls if c[0] == "POST"]) == len(full)  # one request per page


def test_batches_are_chunked(fake, monkeypatch):
    monkeypatch.setattr(osv_mod, "BATCH_SIZE", 2)
    pkgs = [REQ, CLEAN, Pkg(NPM, "lodash", "4.17.15"), Pkg(PYPI, "urllib3", "1.23"), Pkg(NPM, "minimist", "0.0.8")]
    out = client(fake).vuln_ids(pkgs)
    assert list(out) == pkgs  # order preserved
    assert len([c for c in fake.calls if c[0] == "POST"]) == 3
    assert out[Pkg(NPM, "lodash", "4.17.15")] and out[Pkg(NPM, "minimist", "0.0.8")]


def test_results_are_cached(fake):
    c = client(fake)
    c.vuln_ids([REQ])
    c.get_vuln("GHSA-x84v-xcm2-53pg")
    n = len(fake.calls)
    c.vuln_ids([REQ])
    c.get_vuln("GHSA-x84v-xcm2-53pg")
    assert len(fake.calls) == n


def test_get_vulns_concurrent_and_ordered(fake):
    ids = ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28", "CVE-2018-18074"]
    recs = client(fake).get_vulns(ids)
    assert list(recs) == ids and all(recs[i]["id"] == i for i in ids)


def test_unknown_vuln_gives_actionable_error(fake):
    with pytest.raises(NotFoundError, match="OSV has no record 'GHSA-nope'.*CVE-2020-1234"):
        client(fake).get_vuln("GHSA-nope")


def test_retries_429_honouring_retry_after_then_succeeds(fake):
    sleeps: list[float] = []
    fake.fail_next = [(429, "2"), (503, None)]
    c = OSV(Http(sleep=sleeps.append), base=fake.url)
    assert "GHSA-x84v-xcm2-53pg" in c.vuln_ids([REQ])[REQ]
    assert sleeps == [2.0, 1.0]  # Retry-After first, then exponential backoff


def test_persistent_429_becomes_a_clear_rate_limit_error(fake):
    fake.fail_next = [(429, "1")] * 10
    c = OSV(Http(sleep=lambda s: None, retries=2), base=fake.url)
    with pytest.raises(RateLimitError, match="rate limiting.*HTTP 429.*3 attempts.*Wait a minute"):
        c.vuln_ids([REQ])


def test_server_error_is_reported_with_status(fake):
    fake.fail_next = [(500, None)]
    with pytest.raises(NetworkError, match="HTTP 500"):
        OSV(Http(sleep=lambda s: None, retries=0), base=fake.url).vuln_ids([REQ])


def test_unreachable_host_error_mentions_connection():
    with pytest.raises(NetworkError, match="could not reach http://127.0.0.1:9.*internet connection"):
        OSV(Http(timeout=2, retries=0), base="http://127.0.0.1:9").vuln_ids([REQ])


def test_slow_server_times_out(fake):
    fake.delay = 1.5
    with pytest.raises(NetworkError, match="did not answer within 0.5s"):
        OSV(Http(timeout=0.5, retries=0), base=fake.url).vuln_ids([REQ])


def test_non_json_answer_is_an_error(fake):
    fake.garbage = True
    with pytest.raises(NetworkError, match="not JSON"):
        client(fake).vuln_ids([REQ])


def test_registry_latest_for_each_ecosystem(fake, monkeypatch):
    for k, v in fake.env().items():
        monkeypatch.setenv(k, v)
    reg = Registry(Http(sleep=lambda s: None))
    assert reg.latest(PYPI, "Requests") == fake.latest["PyPI|requests"]
    assert reg.latest(NPM, "@babel/core") == fake.latest["npm|@babel/core"]  # scoped name is URL-encoded
    assert reg.latest("crates.io", "smallvec") == fake.latest["crates.io|smallvec"]
    assert reg.latest("Go", "github.com/gin-gonic/gin") == fake.latest["Go|github.com/gin-gonic/gin"]


def test_registry_failures_are_reported_not_dropped(fake, monkeypatch):
    for k, v in fake.env().items():
        monkeypatch.setenv(k, v)
    reg = Registry(Http(sleep=lambda s: None, retries=0))
    found, failed = reg.latest_many([REQ, Pkg(PYPI, "no-such-package-xyz", "1.0")])
    assert (PYPI, "requests") in found
    assert "NotFoundError" in failed[(PYPI, "no-such-package-xyz")]
