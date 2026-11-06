"""depaudit-mcp: an MCP server that audits dependencies via their lockfiles."""

from __future__ import annotations

import functools
import os
import re
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import analysis as an
from . import lockfiles
from . import severity as sev
from . import versions as ver
from .errors import DepauditError, NetworkError
from .model import CRATES, ECOSYSTEMS, GO, NPM, PYPI, Lockfile, Pkg
from .osv import OSV
from .registry import Registry, pypi_normalize

mcp = MCPServer(
    "depaudit",
    instructions=(
        "Audit a project's dependencies by reading its lockfiles (uv.lock, poetry.lock, requirements.txt, "
        "package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, go.sum), so transitive dependencies are "
        "covered. Start with scan_project(path) for known vulnerabilities (OSV.dev) with fixed-in versions and "
        "the dependency path that pulls in each transitive one. suggest_fixes(path) turns that into a minimal "
        "upgrade plan and flags breaking bumps. list_outdated(path) shows packages behind their latest release. "
        "check_package checks a single name+version, explain_vulnerability explains one advisory id. "
        "Everything is read-only: lockfiles are never modified. Needs internet access to api.osv.dev and "
        "the package registries."
    ),
)

_osv = OSV()
_registry = Registry()

F = TypeVar("F", bound=Callable[..., Any])


def tool(fn: F) -> F:
    """Register fn as a tool; expected failures reach the agent as ToolError text
    (MCPServer hides the message of any other exception)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (DepauditError, ValueError) as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


_ECO_ALIASES = {
    "pypi": PYPI, "pip": PYPI, "python": PYPI,
    "npm": NPM, "node": NPM, "javascript": NPM,
    "crates.io": CRATES, "crates": CRATES, "cargo": CRATES, "rust": CRATES,
    "go": GO, "golang": GO,
}


def _ecosystem(name: str) -> str:
    eco = _ECO_ALIASES.get(name.strip().lower())
    if eco is None:
        raise ValueError(f"unknown ecosystem {name!r}. Use one of: {', '.join(ECOSYSTEMS)} (pip/cargo/golang also accepted).")
    return eco


def _load(path: str) -> tuple[str, list[Lockfile]]:
    root = os.path.abspath(os.path.expanduser(path))
    return root, [lockfiles.parse(p) for p in lockfiles.detect(root)]


@tool
def scan_project(path: str, limit: int = 30) -> str:
    """Scan a project's lockfiles for known vulnerabilities (OSV.dev).

    path: a project directory (lockfiles are found up to 3 levels deep, skipping
    node_modules and virtualenvs) or one lockfile. Supports uv.lock, poetry.lock,
    requirements.txt (== pins only), package-lock.json (v2/v3), pnpm-lock.yaml
    (v6-v9), yarn.lock (v1), Cargo.lock and go.sum.

    Reports package counts (direct vs transitive) and, worst first, each
    vulnerable package version with its advisories (GHSA/PYSEC/CVE merged),
    severity, CVSS score, fixed-in version and, for transitive ones, the
    dependency path from a direct dependency. limit caps how many vulnerable
    packages are listed per lockfile. Read-only.
    """
    root, locks = _load(path)
    results = an.audit(locks, _osv)
    return an.scan_report(locks, results, root, max(1, limit))


@tool
def suggest_fixes(path: str) -> str:
    """Propose a minimal upgrade plan for the vulnerabilities in a project's lockfiles.

    For each vulnerable package: the smallest version that fixes every advisory
    (re-checked against OSV so the target is not itself vulnerable), whether the
    bump is breaking (major, or minor on 0.x), the dependency path for
    transitive packages, and the command or manifest change to apply it.
    This tool NEVER modifies files; it only prints the plan.
    """
    _, locks = _load(path)
    results = an.audit(locks, _osv)
    plan = an.plan_fixes(locks, results, _osv)
    return an.fixes_report(locks, plan)


@tool
def list_outdated(path: str, include_transitive: bool = False, limit: int = 40) -> str:
    """List packages in a project's lockfiles that are behind their latest release.

    Compares each locked version with the latest stable version on PyPI, the npm
    registry, crates.io or the Go module proxy, and labels the gap MAJOR, MINOR
    or PATCH (biggest first). By default only direct dependencies are checked;
    set include_transitive=True for everything (more requests; transitive
    packages may be held back by their parents' version ranges). Lookups are
    concurrent and cached; packages whose lookup fails are listed, not hidden.
    """
    _, locks = _load(path)
    res = an.find_outdated(locks, _registry, include_transitive)
    return an.outdated_report(locks, res, include_transitive, max(1, limit))


@tool
def check_package(ecosystem: str, name: str, version: str) -> str:
    """Check one exact package version for known vulnerabilities, without a lockfile.

    ecosystem: PyPI, npm, crates.io or Go. Also reports the latest release and
    how far behind this version is. Example: check_package("PyPI", "requests", "2.19.1").
    """
    eco = _ecosystem(ecosystem)
    name = pypi_normalize(name) if eco == PYPI else name.strip()
    pkg = Pkg(eco, name, version.strip())
    if not pkg.name or not pkg.version:
        raise ValueError("name and version must both be given")
    ids = _osv.vuln_ids([pkg])[pkg]
    advisories = an.build_advisories([_osv.get_vuln(i) for i in ids], pkg) if ids else []
    lines = [f"{eco}: {pkg.label()}"]
    if advisories:
        fnd = an.Finding(pkg, advisories)
        fix = fnd.fix_version()
        lines.append(f"{len(advisories)} known advisories, worst {fnd.severity}"
                     + (f"; upgrade to >= {fix}" if fix else "; no single fixed version known"))
        for a in advisories:
            score = f" CVSS {a.score:.1f}" if a.score is not None else ""
            fx = f", fixed in {a.fixed}" if a.fixed else ", no fix known"
            lines.append(f"  - {a.names()} {a.severity}{score}{fx}: {a.summary}")
    else:
        lines.append("No known vulnerabilities in OSV.dev for this exact version.")
    try:
        latest = _registry.latest(eco, pkg.name)
    except (NetworkError, KeyError) as e:
        lines.append(f"latest version: lookup failed ({e})")
    else:
        kind = ver.bump_kind(pkg.version, latest)
        lines.append(f"latest version: {latest}" + (f" ({kind} update available)" if kind else " (up to date)"))
    return "\n".join(lines)


@tool
def explain_vulnerability(id: str) -> str:
    """Explain one advisory: summary, severity, affected version ranges, fix, references.

    id: an OSV-known id such as GHSA-x84v-xcm2-53pg, CVE-2018-18074,
    PYSEC-2018-28 or RUSTSEC-2020-0071.
    """
    vid = id.strip()
    if not vid:
        raise ValueError("pass an advisory id such as GHSA-x84v-xcm2-53pg or CVE-2018-18074")
    raw = _osv.get_vuln(vid)
    label, score = sev.of_record(raw)
    lines = [f"{raw['id']}: {raw.get('summary') or '(no summary)'}"]
    if raw.get("withdrawn"):
        lines.append(f"WITHDRAWN on {raw['withdrawn']}: this advisory was retracted.")
    sevline = f"severity: {label}" + (f" (CVSS {score:.1f})" if score is not None else "")
    vectors = [s["score"] for s in raw.get("severity", []) if isinstance(s.get("score"), str)]
    if vectors:
        sevline += "  " + " ".join(vectors)
    lines.append(sevline)
    if raw.get("aliases"):
        lines.append("aliases: " + ", ".join(raw["aliases"]))
    if raw.get("published"):
        lines.append(f"published: {raw['published']}  modified: {raw.get('modified', '?')}")
    details = (raw.get("details") or "").strip()
    if details:
        lines.append("")
        lines.append(re.sub(r"\n{3,}", "\n\n", details)[:1500] + (" ..." if len(details) > 1500 else ""))
    lines.append("")
    lines.append("affected:")
    for aff in raw.get("affected", []) or []:
        p = aff.get("package") or {}
        label_pkg = f"{p.get('ecosystem', '?')}:{p.get('name', '?')}"
        spans: list[str] = []
        for rng in aff.get("ranges", []) or []:
            start: str | None = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    start = ev["introduced"]
                elif "fixed" in ev:
                    spans.append(f"{'start' if start in (None, '0') else start} <= v < {ev['fixed']}  (fixed in {ev['fixed']})")
                    start = None
                elif "last_affected" in ev:
                    spans.append(f"{'start' if start in (None, '0') else start} <= v <= {ev['last_affected']}  (no fix)")
                    start = None
            if start is not None:
                spans.append(f"{'all versions' if start == '0' else 'v >= ' + start} (no fix)")
        if not spans and aff.get("versions"):
            vs = aff["versions"]
            spans.append(f"{len(vs)} listed versions: " + ", ".join(vs[:6]) + (" ..." if len(vs) > 6 else ""))
        lines.append(f"  {label_pkg}: " + ("; ".join(spans[:6]) if spans else "(no range data)"))
    if not raw.get("affected"):
        lines.append("  (no package data)")
    refs = raw.get("references") or []
    if refs:
        lines.append("")
        lines.append("references:")
        for r in refs[:8]:
            lines.append(f"  [{r.get('type', 'WEB')}] {r.get('url')}")
        if len(refs) > 8:
            lines.append(f"  ... {len(refs) - 8} more")
    return "\n".join(lines)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
