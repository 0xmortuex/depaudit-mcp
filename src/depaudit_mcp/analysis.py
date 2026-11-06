"""Turn lockfiles + OSV records + registry data into the reports the tools return."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import severity as sev
from . import versions as ver
from .errors import DepauditError
from .model import PYPI, Lockfile, Pkg
from .osv import OSV
from .registry import Registry, pypi_normalize


@dataclass
class Advisory:
    """One real-world issue, merging the OSV records (GHSA/PYSEC/CVE/...) that alias each other."""

    ids: list[str]  # primary id first
    aliases: list[str]
    summary: str
    severity: str
    score: float | None
    fixed: str | None  # smallest version above the installed one that fixes it, if known

    @property
    def primary(self) -> str:
        return self.ids[0]

    def names(self) -> str:
        others = [i for i in dict.fromkeys([*self.ids[1:], *self.aliases]) if i != self.primary]
        cves = [i for i in others if i.startswith("CVE-")]
        return self.primary + (f" ({', '.join(cves)})" if cves else "")


@dataclass
class Finding:
    pkg: Pkg
    advisories: list[Advisory]

    @property
    def severity(self) -> str:
        return min((a.severity for a in self.advisories), key=sev.rank)

    def fix_version(self) -> str | None:
        """Smallest version that fixes every advisory, or None if any has no known fix."""
        fixes = [a.fixed for a in self.advisories]
        if not fixes or any(f is None for f in fixes):
            return None
        best = max((f for f in fixes if f), key=lambda v: ver.parse(v) or ((), 0, ()))
        return best


# ---------------------------------------------------------------- OSV record handling


def _norm_name(ecosystem: str, name: str) -> str:
    return pypi_normalize(name) if ecosystem == PYPI else name


def fixed_versions(raw: dict[str, Any], pkg: Pkg) -> list[str]:
    """Every 'fixed' event in the record's ECOSYSTEM/SEMVER ranges for this package."""
    out: list[str] = []
    for aff in raw.get("affected", []) or []:
        p = aff.get("package") or {}
        if p.get("ecosystem") != pkg.ecosystem or _norm_name(pkg.ecosystem, p.get("name", "")) != pkg.name:
            continue
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return out


def fixed_in(raw: dict[str, Any], pkg: Pkg) -> str | None:
    """Smallest fixed version newer than the installed one."""
    best: str | None = None
    for f in fixed_versions(raw, pkg):
        c = ver.compare(pkg.version, f)
        if c is None or c >= 0:
            continue
        if best is None or ver.compare(f, best) == -1:
            best = f
    return best


def build_advisories(records: list[dict[str, Any]], pkg: Pkg) -> list[Advisory]:
    """Merge records that alias each other and compute severity and fix per issue."""
    records = [r for r in records if not r.get("withdrawn")]
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, r in enumerate(records):
        for name in [r["id"], *r.get("aliases", [])]:
            if name in owner:
                parent[find(i)] = find(owner[name])
            else:
                owner[name] = i
    groups: dict[int, list[dict[str, Any]]] = {}
    for i, r in enumerate(records):
        groups.setdefault(find(i), []).append(r)

    out: list[Advisory] = []
    for members in groups.values():
        members.sort(key=lambda r: (not r["id"].startswith("GHSA-"), r["id"]))
        ids = [r["id"] for r in members]
        aliases = sorted({a for r in members for a in r.get("aliases", [])} - set(ids))
        rated = [sev.of_record(r) for r in members]
        best = min(rated, key=lambda t: (sev.rank(t[0]), -(t[1] or 0)))
        fixes = [f for r in members if (f := fixed_in(r, pkg))]
        fixed = max(fixes, key=lambda v: ver.parse(v) or ((), 0, ())) if fixes else None
        summary = next((r["summary"] for r in members if r.get("summary")), None)
        if summary is None:
            detail = next((r["details"] for r in members if r.get("details")), "")
            summary = detail.strip().splitlines()[0][:120] if detail.strip() else "(no summary)"
        out.append(Advisory(ids, aliases, summary, best[0], best[1], fixed))
    out.sort(key=lambda a: (sev.rank(a.severity), a.primary))
    return out


def audit(locks: list[Lockfile], osv: OSV) -> dict[str, list[Finding]]:
    """Findings per lockfile path, worst first. One OSV batch covers all lockfiles."""
    every = sorted({p for lk in locks for p in lk.packages})
    ids_by_pkg = osv.vuln_ids(every)
    records = osv.get_vulns(i for ids in ids_by_pkg.values() for i in ids)
    findings_by_pkg: dict[Pkg, Finding] = {}
    for pkg, ids in ids_by_pkg.items():
        if ids:
            adv = build_advisories([records[i] for i in ids], pkg)
            if adv:
                findings_by_pkg[pkg] = Finding(pkg, adv)
    out: dict[str, list[Finding]] = {}
    for lk in locks:
        found = [findings_by_pkg[p] for p in lk.packages if p in findings_by_pkg]
        found.sort(key=lambda f: (sev.rank(f.severity), f.pkg.name, f.pkg.version))
        out[lk.path] = found
    return out


# ---------------------------------------------------------------- dependency paths


def paths_from_roots(lock: Lockfile) -> dict[Pkg, Pkg | None]:
    """Breadth-first parent pointers from all direct packages (None = it is a root)."""
    parent: dict[Pkg, Pkg | None] = {p: None for p in sorted(lock.direct)}
    queue = list(parent)
    while queue:
        cur = queue.pop(0)
        for nxt in sorted(lock.edges.get(cur, ())):
            if nxt not in parent:
                parent[nxt] = cur
                queue.append(nxt)
    return parent


def path_to(parent: dict[Pkg, Pkg | None], pkg: Pkg) -> list[Pkg] | None:
    """Shortest chain direct -> ... -> pkg, or None if no direct package reaches it."""
    if pkg not in parent:
        return None
    chain = [pkg]
    while (p := parent[chain[-1]]) is not None:
        chain.append(p)
    return chain[::-1]


def fmt_path(chain: list[Pkg]) -> str:
    return " > ".join(p.label() for p in chain)


# ---------------------------------------------------------------- scan report

MAX_ADVISORIES = 5  # per package in scan output; the rest are summarised


def _count_by_severity(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        for a in f.advisories:
            counts[a.severity] = counts.get(a.severity, 0) + 1
    return ", ".join(f"{counts[s]} {s}" for s in sev.ORDER if s in counts)


def scan_report(locks: list[Lockfile], results: dict[str, list[Finding]], root: str, limit: int) -> str:
    total_adv = sum(len(f.advisories) for fs in results.values() for f in fs)
    lines = [f"depaudit scan of {root}"]
    for lk in locks:
        n = len(lk.packages)
        lines.append(f"  {lk.kind}: {n} packages, {len(lk.direct)} direct, {n - len(lk.direct)} transitive  [{lk.path}]")
    if total_adv == 0:
        lines.append("No known vulnerabilities found (OSV.dev). Note: this only covers published advisories for the exact locked versions.")
    else:
        pkgs = sum(len(fs) for fs in results.values())
        lines.append(f"{total_adv} advisories across {pkgs} vulnerable package versions: " + _count_by_severity(
            [f for fs in results.values() for f in fs]))
    for lk in locks:
        fs = results[lk.path]
        if not fs and not lk.notes:
            continue
        lines.append("")
        lines.append(f"== {lk.kind} ({lk.path})")
        parents = paths_from_roots(lk)
        for f in fs[:limit]:
            kind = "direct" if f.pkg in lk.direct else "transitive"
            fix = f.fix_version()
            lines.append(
                f"{f.severity:<8} {f.pkg.label()} [{kind}]  "
                + (f"fix: upgrade to >= {fix}" if fix else "fix: no fixed version known for at least one advisory")
            )
            for a in f.advisories[:MAX_ADVISORIES]:
                score = f" CVSS {a.score:.1f}" if a.score is not None else ""
                fx = f", fixed in {a.fixed}" if a.fixed else ", no fix known"
                lines.append(f"    - {a.names()} {a.severity}{score}{fx}: {_clip(a.summary, 90)}")
            if len(f.advisories) > MAX_ADVISORIES:
                lines.append(f"    ... and {len(f.advisories) - MAX_ADVISORIES} more, lower severity (check_package lists all)")
            if f.pkg not in lk.direct:
                chain = path_to(parents, f.pkg)
                lines.append("    via: " + (fmt_path(chain) if chain else _no_path(lk)))
        if len(fs) > limit:
            lines.append(f"... {len(fs) - limit} more vulnerable packages not shown (raise limit=)")
        for note in lk.notes:
            lines.append(f"note: {note}")
    return "\n".join(lines)


def _no_path(lk: Lockfile) -> str:
    if not lk.edges:
        return f"unknown ({lk.kind} records no dependency graph)"
    return "unknown (no path from a direct dependency; it may be an optional or platform-specific dependency)"


def _clip(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------- outdated


@dataclass
class Outdated:
    pkg: Pkg
    latest: str
    kind: str  # major / minor / patch
    direct: bool


@dataclass
class OutdatedResult:
    rows: dict[str, list[Outdated]] = field(default_factory=dict)  # per lockfile path
    checked: dict[str, int] = field(default_factory=dict)
    failed: dict[tuple[str, str], str] = field(default_factory=dict)


def find_outdated(locks: list[Lockfile], reg: Registry, include_transitive: bool) -> OutdatedResult:
    res = OutdatedResult()
    wanted: list[Pkg] = []
    for lk in locks:
        wanted += sorted(lk.packages if include_transitive else lk.direct)
    latest, failed = reg.latest_many(wanted)
    if wanted and not latest:
        first = next(iter(failed.values()))
        raise DepauditError(f"could not look up the latest version of any package ({len(failed)} failures). First error: {first}")
    res.failed = failed
    for lk in locks:
        pkgs = sorted(lk.packages if include_transitive else lk.direct)
        res.checked[lk.path] = len(pkgs)
        rows: list[Outdated] = []
        for p in pkgs:
            lt = latest.get((p.ecosystem, p.name))
            if lt is None:
                continue
            kind = ver.bump_kind(p.version, lt)
            if kind:
                rows.append(Outdated(p, lt, kind, p in lk.direct))
        order = {"major": 0, "minor": 1, "patch": 2}
        rows.sort(key=lambda r: (order[r.kind], not r.direct, r.pkg.name))
        res.rows[lk.path] = rows
    return res


def outdated_report(locks: list[Lockfile], res: OutdatedResult, include_transitive: bool, limit: int) -> str:
    scope = "all packages" if include_transitive else "direct dependencies"
    lines = [f"Outdated check ({scope}); latest stable versions from the registries"]
    for lk in locks:
        rows = res.rows[lk.path]
        lines.append("")
        lines.append(f"== {lk.kind} ({lk.path}): {len(rows)} of {res.checked[lk.path]} behind")
        for r in rows[:limit]:
            tag = "" if r.direct else " [transitive]"
            lines.append(f"{r.kind.upper():<5} {r.pkg.name} {r.pkg.version} -> {r.latest}{tag}")
        if len(rows) > limit:
            lines.append(f"... {len(rows) - limit} more not shown (raise limit=)")
        for note in lk.notes:
            lines.append(f"note: {note}")
    if res.failed:
        lines.append("")
        lines.append(f"Could not look up {len(res.failed)} package(s):")
        for (eco, name), err in list(res.failed.items())[:10]:
            lines.append(f"  {eco}:{name}: {_clip(err, 140)}")
    if include_transitive:
        lines.append("")
        lines.append("Transitive packages may be held back by their parents' version ranges; upgrade the direct dependency instead.")
    return "\n".join(lines)


# ---------------------------------------------------------------- fix plan


@dataclass
class FixStep:
    pkg: Pkg
    target: str | None
    direct: bool
    breaking: bool
    advisories: list[Advisory]
    via: list[Pkg] | None
    still_vulnerable: list[str] = field(default_factory=list)


MAX_VERIFY_ROUNDS = 4


def plan_fixes(locks: list[Lockfile], results: dict[str, list[Finding]], osv: OSV) -> dict[str, list[FixStep]]:
    """Minimal upgrade per vulnerable package: the smallest version fixing every
    advisory, re-checked against OSV so the target itself is not vulnerable."""
    targets: dict[Pkg, str | None] = {}
    for fs in results.values():
        for f in fs:
            targets[f.pkg] = f.fix_version()
    # verify each target; if it is still affected, move to what fixes that
    unresolved: dict[Pkg, list[str]] = {}
    for _ in range(MAX_VERIFY_ROUNDS):
        probes = {p: Pkg(p.ecosystem, p.name, t) for p, t in targets.items() if t and p not in unresolved}
        if not probes:
            break
        ids = osv.vuln_ids(probes.values())
        records = osv.get_vulns(i for lst in ids.values() for i in lst)
        changed = False
        for orig, probe in probes.items():
            if not ids[probe]:
                continue
            adv = build_advisories([records[i] for i in ids[probe]], probe)
            if not adv:
                continue
            fixes = [a.fixed for a in adv]
            if all(fixes):
                best = max((f for f in fixes if f), key=lambda v: ver.parse(v) or ((), 0, ()))
                targets[orig] = best
                changed = True
            else:
                unresolved[orig] = [a.primary for a in adv]
        if not changed:
            break
    out: dict[str, list[FixStep]] = {}
    for lk in locks:
        parents = paths_from_roots(lk)
        steps: list[FixStep] = []
        for f in results[lk.path]:
            target = targets[f.pkg]
            steps.append(FixStep(
                f.pkg, target, f.pkg in lk.direct,
                bool(target) and ver.is_breaking(f.pkg.version, target or ""),
                f.advisories,
                None if f.pkg in lk.direct else path_to(parents, f.pkg),
                unresolved.get(f.pkg, []),
            ))
        out[lk.path] = steps
    return out


_HINTS = {
    "uv.lock": (
        'raise the constraint in pyproject.toml to >={target} if it pins lower, then: uv lock --upgrade-package "{name}"',
        'uv lock --upgrade-package "{name}"  (if the parent holds it back, upgrade the parent or add "{name}>={target}" to constraint-dependencies)',
    ),
    "poetry.lock": ("poetry add {name}@{target}", "poetry update {name}  (or raise the parent)"),
    "requirements.txt": ("change the pin to {name}=={target}", "change the pin to {name}=={target}"),
    "package-lock.json": ("npm install {name}@{target}", 'upgrade the parent, or add "overrides": {{"{name}": "{target}"}} to package.json'),
    "pnpm-lock.yaml": ("pnpm add {name}@{target}", 'upgrade the parent, or add "pnpm": {{"overrides": {{"{name}": "{target}"}}}} to package.json'),
    "yarn.lock": ("yarn add {name}@{target}", 'upgrade the parent, or add "resolutions": {{"{name}": "{target}"}} to package.json'),
    "Cargo.lock": ("cargo update -p {name} --precise {target}", "cargo update -p {name} --precise {target}  (needs the parent's version requirement to allow it)"),
    "go.sum": ("go get {name}@{target}", "go get {name}@{target}"),
}


def fixes_report(locks: list[Lockfile], plan: dict[str, list[FixStep]]) -> str:
    lines = ["Fix plan - read-only: nothing was modified. Targets are the smallest versions that fix every advisory and are not themselves known-vulnerable."]
    any_steps = False
    for lk in locks:
        steps = plan[lk.path]
        if not steps:
            continue
        any_steps = True
        lines.append("")
        lines.append(f"== {lk.kind} ({lk.path})")
        direct_hint, trans_hint = _HINTS[lk.kind]
        for n, s in enumerate(steps, 1):
            kind = "direct" if s.direct else "transitive"
            worst = min((a.severity for a in s.advisories), key=sev.rank)
            if s.target is None:
                lines.append(f"{n}. {s.pkg.label()} [{kind}] {worst}: no fixed version is known for at least one advisory. "
                             "Check explain_vulnerability for mitigations or replace the package.")
            else:
                kind_of_bump = ver.bump_kind(s.pkg.version, s.target) or "?"
                warn = "  BREAKING: major/0.x bump, read the changelog and run tests" if s.breaking else ""
                lines.append(f"{n}. {s.pkg.name} {s.pkg.version} -> {s.target}  [{kind}, {kind_of_bump}] fixes {len(s.advisories)} advisory/ies, worst {worst}{warn}")
                hint = (direct_hint if s.direct else trans_hint).format(name=s.pkg.name, target=s.target)
                lines.append(f"     do: {hint}")
            if s.via:
                lines.append(f"     pulled in by: {fmt_path(s.via)}")
            elif not s.direct:
                lines.append(f"     pulled in by: {_no_path(lk)}")
            if s.still_vulnerable:
                lines.append(f"     warning: {s.target} still has {', '.join(s.still_vulnerable)} with no known fix")
    if not any_steps:
        lines.append("")
        lines.append("Nothing to fix: no known vulnerabilities.")
    return "\n".join(lines)
