"""The five tools end to end on real lockfiles, with OSV/registry replayed from recordings."""

import hashlib
import os

import pytest

from depaudit_mcp import server
from depaudit_mcp import versions as ver
from depaudit_mcp.errors import LockfileError


def tree_hash(path):
    h = hashlib.sha256()
    for root, _, files in sorted(os.walk(path)):
        for f in sorted(files):
            p = os.path.join(root, f)
            h.update(p.encode())
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


@pytest.mark.parametrize(
    "project,needle",
    [
        ("uv", "requests 2.19.1 [direct]"),
        ("poetry", "requests 2.19.1 [direct]"),
        ("requirements", "requests 2.19.1 [direct]"),
        ("npm", "lodash 4.17.15 [direct]"),
        ("pnpm9", "lodash 4.17.15 [direct]"),
        ("pnpm6", "lodash 4.17.15 [direct]"),
        ("yarn", "lodash 4.17.15 [direct]"),
        ("cargo", "smallvec 0.6.9 [direct]"),
        ("go", "github.com/gin-gonic/gin v1.6.3 [direct]"),
    ],
)
def test_scan_reports_the_known_vulnerable_pin(offline, fix, project, needle):
    out = server.scan_project(fix(project))
    assert needle in out
    assert "fixed in" in out
    assert offline.unrecorded == []


def test_scan_shows_dependency_path_for_transitive(offline, fix):
    out = server.scan_project(fix("npm"))
    assert "minimist 0.0.8 [transitive]" in out
    assert "via: mkdirp 0.5.1 > minimist 0.0.8" in out
    out = server.scan_project(fix("uv"))
    assert "via: requests 2.19.1 > urllib3 1.23" in out


def test_scan_is_severity_sorted_and_deduplicated(offline, fix):
    out = server.scan_project(fix("npm"))
    heads = [ln.split()[0] for ln in out.splitlines() if ln.split() and ln.split()[0] in
             ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN") and "[" in ln]
    order = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]
    assert heads == sorted(heads, key=order.index) and heads[0] == "CRITICAL"
    # GHSA + CVE (+ PYSEC) describe one issue: each GHSA id is listed once, with its CVE in brackets
    out = server.scan_project(fix("requirements"))
    ghsa = [w for w in out.split() if w.startswith("GHSA-")]
    assert len(ghsa) == len(set(ghsa))
    assert "GHSA-x84v-xcm2-53pg (CVE-2018-18074)" in out
    assert "PYSEC-2018-28" not in out.split("GHSA-x84v-xcm2-53pg")[1].split("\n")[0]


def test_scan_counts_direct_and_transitive(offline, fix):
    out = server.scan_project(fix("npm"))
    assert "35 packages, 3 direct, 32 transitive" in out


def test_scan_limit_truncates_with_a_note(offline, fix):
    out = server.scan_project(fix("npm"), limit=1)
    assert "more vulnerable packages not shown" in out


def test_scan_accepts_a_single_lockfile_path(offline, fix):
    out = server.scan_project(os.path.join(fix("uv"), "uv.lock"))
    assert "uv.lock" in out and "requests 2.19.1" in out


def test_scan_multiple_lockfiles_in_one_directory(offline, fix, tmp_path):
    for sub in ("uv", "npm"):
        d = tmp_path / sub
        d.mkdir()
        for name in os.listdir(fix(sub)):
            (d / name).write_bytes(open(os.path.join(fix(sub), name), "rb").read())
    out = server.scan_project(str(tmp_path))
    assert "== uv.lock" in out and "== package-lock.json" in out


def test_clean_project_says_so(offline, tmp_path):
    (tmp_path / "requirements.txt").write_text("certifi==2026.10.23\n", encoding="utf-8")
    out = server.scan_project(str(tmp_path))
    assert "No known vulnerabilities" in out


def test_scan_errors_reach_the_agent_as_toolerror(offline, tmp_path):
    with pytest.raises(LockfileError, match="no lockfile found"):
        server.scan_project(str(tmp_path))


def test_check_package(offline):
    out = server.check_package("pypi", "Requests", "2.19.1")
    assert "GHSA-x84v-xcm2-53pg (CVE-2018-18074) HIGH CVSS 7.5, fixed in 2.20.0" in out
    assert "latest version:" in out and "update available" in out
    with pytest.raises(ValueError, match="unknown ecosystem 'maven'"):
        server.check_package("maven", "x", "1")


def test_explain_vulnerability(offline):
    out = server.explain_vulnerability("GHSA-x84v-xcm2-53pg")
    assert "severity: HIGH (CVSS 7.5)" in out
    assert "PyPI:requests: start <= v < 2.20.0  (fixed in 2.20.0)" in out
    assert "CVE-2018-18074" in out and "references:" in out
    with pytest.raises(Exception, match="OSV has no record"):
        server.explain_vulnerability("GHSA-does-not-exist")
    with pytest.raises(ValueError, match="pass an advisory id"):
        server.explain_vulnerability("  ")


def test_list_outdated(offline, fix):
    out = server.list_outdated(fix("npm"))
    assert "MAJOR mkdirp 0.5.1 ->" in out
    assert "MINOR lodash 4.17.15 ->" in out
    assert out.index("MAJOR") < out.index("MINOR")  # biggest gap first
    assert "[transitive]" not in out
    full = server.list_outdated(fix("uv"), include_transitive=True)
    assert "[transitive]" in full


def test_list_outdated_reports_failed_lookups(offline, fix, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\nnot-recorded-pkg==1.0\n", encoding="utf-8")
    out = server.list_outdated(str(tmp_path))
    assert "requests 2.19.1 ->" in out
    assert "Could not look up 1 package" in out and "not-recorded-pkg" in out


def test_list_outdated_fails_loudly_when_registry_is_down(offline, fix):
    offline.fail_next = [(500, None)] * 100
    with pytest.raises(Exception, match="could not look up the latest version of any package"):
        server.list_outdated(fix("npm"))


def test_suggest_fixes_plan(offline, fix):
    out = server.suggest_fixes(fix("npm"))
    assert "read-only: nothing was modified" in out
    # minimist is pulled in by mkdirp and is a 0.x bump: flagged breaking, with the parent shown
    block = out.split("1. minimist")[1].split("\n2.")[0]
    assert "BREAKING" in block and "pulled in by: mkdirp 0.5.1 > minimist 0.0.8" in block and "overrides" in block
    # json5 0.5.1 -> 1.x is a major bump
    assert "json5 0.5.1 -> 1." in out
    # lodash direct: a patch/minor bump, not breaking, with the npm command
    lodash = out.split("lodash 4.17.15 ->")[1].split("\n")
    assert "BREAKING" not in lodash[0] and "do: npm install lodash@" in lodash[1]


def test_suggest_fixes_target_is_not_itself_vulnerable(offline, fix):
    """OSV lists lodash 4.18.0 as fixed for one advisory, but 4.18.0 itself is affected by another:
    the plan must move on to a version OSV considers clean."""
    out = server.suggest_fixes(fix("npm"))
    target = out.split("lodash 4.17.15 -> ")[1].split()[0]
    assert ver.compare(target, "4.17.21") == 1
    ids = server._osv.vuln_ids([server.Pkg("npm", "lodash", target)])
    assert list(ids.values()) == [[]]


def test_suggest_fixes_never_modifies_files(offline, fix):
    before = tree_hash(fix("uv")), tree_hash(fix("npm")), tree_hash(fix("cargo"))
    server.suggest_fixes(fix("uv"))
    server.suggest_fixes(fix("npm"))
    server.suggest_fixes(fix("cargo"))
    server.scan_project(fix("uv"))
    server.list_outdated(fix("uv"))
    assert before == (tree_hash(fix("uv")), tree_hash(fix("npm")), tree_hash(fix("cargo")))


def test_suggest_fixes_clean_project(offline, tmp_path):
    (tmp_path / "requirements.txt").write_text("certifi==2026.10.23\n", encoding="utf-8")
    assert "Nothing to fix" in server.suggest_fixes(str(tmp_path))
