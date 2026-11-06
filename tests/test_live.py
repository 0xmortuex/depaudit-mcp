"""Tests against the REAL OSV.dev and registry APIs. Deselected by default; run with

    pytest -m live

They assert on facts that do not change: a pinned, long-known-vulnerable version stays
vulnerable, and the advisory ids stay valid."""

import os

import pytest

from depaudit_mcp import server
from depaudit_mcp.model import NPM, PYPI, Pkg
from depaudit_mcp.osv import OSV
from depaudit_mcp.registry import Registry

pytestmark = pytest.mark.live
FIX = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(autouse=True)
def fresh_clients(monkeypatch):
    monkeypatch.setattr(server, "_osv", OSV())
    monkeypatch.setattr(server, "_registry", Registry())


def test_live_requests_2_19_1_is_reported():
    out = server.check_package("PyPI", "requests", "2.19.1")
    assert "GHSA-x84v-xcm2-53pg" in out and "CVE-2018-18074" in out and "fixed in 2.20.0" in out


def test_live_lodash_4_17_15_is_reported():
    out = server.check_package("npm", "lodash", "4.17.15")
    assert "CVE-2020-8203" in out or "CVE-2021-23337" in out


def test_live_batch_scan_of_a_lockfile_with_transitive_path():
    out = server.scan_project(os.path.join(FIX, "npm"))
    assert "lodash 4.17.15 [direct]" in out
    assert "via: mkdirp 0.5.1 > minimist 0.0.8" in out


def test_live_batch_returns_ids_for_many_packages_at_once():
    pkgs = [Pkg(PYPI, "requests", "2.19.1"), Pkg(NPM, "lodash", "4.17.15"), Pkg(PYPI, "certifi", "2099.1.1")]
    out = OSV().vuln_ids(pkgs)
    assert out[pkgs[0]] and out[pkgs[1]] and out[pkgs[2]] == []


def test_live_outdated_for_each_registry():
    reg = Registry()
    assert reg.latest(PYPI, "requests")[0].isdigit()
    assert reg.latest(NPM, "@babel/core")[0].isdigit()
    assert reg.latest("crates.io", "smallvec")[0].isdigit()
    assert reg.latest("Go", "github.com/gin-gonic/gin").startswith("v")
    out = server.list_outdated(os.path.join(FIX, "requirements"))
    assert "requests 2.19.1 ->" in out


def test_live_explain_vulnerability():
    out = server.explain_vulnerability("GHSA-x84v-xcm2-53pg")
    assert "PyPI:requests" in out and "2.20.0" in out


def test_live_fix_plan_target_is_clean():
    out = server.suggest_fixes(os.path.join(FIX, "requirements"))
    target = out.split("requests 2.19.1 -> ")[1].split()[0]
    assert server._osv.vuln_ids([Pkg(PYPI, "requests", target)]) == {Pkg(PYPI, "requests", target): []}
