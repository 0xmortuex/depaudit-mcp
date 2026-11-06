"""Lockfile parsers: uv.lock, poetry.lock, requirements.txt, package-lock.json,
pnpm-lock.yaml, yarn.lock (v1), Cargo.lock and go.sum.

Each parser reads one file (and, where the lockfile does not record them, the
manifest next to it to learn which packages are direct) and returns a Lockfile.
Nothing is written to disk.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable
from typing import Any

from .errors import LockfileError
from .model import CRATES, GO, NPM, PYPI, Lockfile, Pkg

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__", "target", "dist", "build",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor", ".idea", ".vscode",
}
MAX_DEPTH = 3
SUPPORTED = "uv.lock, poetry.lock, requirements*.txt, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, go.sum"


def _kind_of(filename: str) -> str | None:
    if filename in ("uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "go.sum"):
        return filename
    if re.fullmatch(r"requirements[-_.\w]*\.txt", filename):
        return "requirements.txt"
    return None


def detect(path: str) -> list[str]:
    """Lockfiles at `path` (a lockfile, or a directory searched up to
    MAX_DEPTH levels deep, skipping node_modules, virtualenvs and the like)."""
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isfile(path):
        if _kind_of(os.path.basename(path)) is None:
            raise LockfileError(f"{path} is not a supported lockfile. Supported: {SUPPORTED}.")
        return [path]
    if not os.path.isdir(path):
        raise LockfileError(f"{path} does not exist. Pass a project directory or a lockfile path.")
    found: list[str] = []
    base_depth = path.rstrip("\\/").count(os.sep)
    for root, dirs, files in os.walk(path):
        depth = root.rstrip("\\/").count(os.sep) - base_depth
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and depth < MAX_DEPTH)
        for f in sorted(files):
            if _kind_of(f):
                found.append(os.path.join(root, f))
    if not found:
        raise LockfileError(
            f"no lockfile found under {path} (looked {MAX_DEPTH} levels deep). Supported: {SUPPORTED}. "
            "Generate one first, for example `uv lock`, `npm install --package-lock-only` or `cargo generate-lockfile`."
        )
    return found


def parse(path: str) -> Lockfile:
    kind = _kind_of(os.path.basename(path))
    if kind is None:
        raise LockfileError(f"{path} is not a supported lockfile. Supported: {SUPPORTED}.")
    parser = _PARSERS[kind]
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise LockfileError(f"cannot read {path}: {e.strerror or e}") from e
    except UnicodeDecodeError as e:
        raise LockfileError(f"{path} is not valid UTF-8 text: {e}") from e
    try:
        return parser(path, text)
    except LockfileError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, tomllib.TOMLDecodeError) as e:
        raise LockfileError(f"{path} does not look like a valid {kind}: {type(e).__name__}: {e}") from e


# ---------------------------------------------------------------- shared helpers


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _read_text_if_exists(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _roots_fallback(lock: Lockfile, why: str) -> None:
    """No manifest to say what is direct: treat packages nothing else depends on
    as direct, and say so."""
    depended = {d for deps in lock.edges.values() for d in deps}
    lock.direct = {p for p in lock.packages if p not in depended} or set(lock.packages)
    lock.notes.append(f"{why}; packages that nothing else depends on are treated as direct")


def _pyproject_direct_names(directory: str) -> set[str] | None:
    """Direct dependency names declared in pyproject.toml (PEP 621, dependency
    groups, Poetry), or None if there is no pyproject.toml."""
    text = _read_text_if_exists(os.path.join(directory, "pyproject.toml"))
    if text is None:
        return None
    data = tomllib.loads(text)
    names: set[str] = set()

    def from_specs(specs: Any) -> None:
        for s in specs or []:
            if isinstance(s, str) and (m := _REQ_NAME.match(s)):
                names.add(_pypi_name(m.group(1)))

    project = data.get("project", {})
    from_specs(project.get("dependencies"))
    for group in (project.get("optional-dependencies") or {}).values():
        from_specs(group)
    for group in (data.get("dependency-groups") or {}).values():
        from_specs(group)
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values()]
    for table in tables:
        for dep in (table or {}):
            if dep.lower() != "python":
                names.add(_pypi_name(dep))
    return names


# ---------------------------------------------------------------- uv.lock


def parse_uv_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "uv.lock", PYPI)
    entries: list[dict[str, Any]] = data.get("package", [])
    by_name: dict[str, list[Pkg]] = {}
    audited: dict[int, Pkg] = {}
    for i, e in enumerate(entries):
        source = e.get("source", {})
        if "registry" in source and "version" in e:
            pkg = Pkg(PYPI, _pypi_name(e["name"]), e["version"])
            audited[i] = pkg
            by_name.setdefault(pkg.name, []).append(pkg)
            lock.packages.add(pkg)

    def resolve(dep: dict[str, Any]) -> Pkg | None:
        candidates = by_name.get(_pypi_name(dep["name"]), [])
        if "version" in dep:
            return next((c for c in candidates if c.version == dep["version"]), None)
        return candidates[0] if len(candidates) == 1 else None

    def dep_lists(e: dict[str, Any]) -> list[dict[str, Any]]:
        out = list(e.get("dependencies", []))
        for group in (e.get("optional-dependencies") or {}).values():
            out += group
        for group in (e.get("dev-dependencies") or {}).values():
            out += group
        return out

    have_root = False
    for i, e in enumerate(entries):
        source = e.get("source", {})
        if i in audited:
            for dep in e.get("dependencies", []):
                target = resolve(dep)
                if target:
                    lock.add_edge(audited[i], target)
        elif "virtual" in source or "editable" in source:
            have_root = True
            for dep in dep_lists(e):
                target = resolve(dep)
                if target:
                    lock.direct.add(target)
    if not have_root:
        _roots_fallback(lock, "uv.lock lists no project package")
    return lock


# ---------------------------------------------------------------- poetry.lock


def parse_poetry_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "poetry.lock", PYPI)
    by_name: dict[str, Pkg] = {}
    entries = data.get("package", [])
    for e in entries:
        src = e.get("source", {}).get("type")
        if src in ("git", "directory", "file", "url"):
            lock.notes.append(f"{e['name']} comes from a {src} source and is not audited")
            continue
        pkg = Pkg(PYPI, _pypi_name(e["name"]), e["version"])
        by_name[pkg.name] = pkg
        lock.packages.add(pkg)
    for e in entries:
        src_pkg = by_name.get(_pypi_name(e["name"]))
        if src_pkg is None:
            continue
        for dep in e.get("dependencies", {}):
            target = by_name.get(_pypi_name(dep))
            if target:
                lock.add_edge(src_pkg, target)
    direct_names = _pyproject_direct_names(os.path.dirname(path))
    if direct_names is None:
        _roots_fallback(lock, "no pyproject.toml next to poetry.lock")
    else:
        lock.direct = {p for p in lock.packages if p.name in direct_names}
    return lock


# ---------------------------------------------------------------- requirements.txt

_REQ_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)


def parse_requirements(path: str, text: str) -> Lockfile:
    lock = Lockfile(path, "requirements.txt", PYPI)
    unpinned: list[str] = []
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append(buf + line)
        buf = ""
    if buf:
        logical.append(buf)
    for line in logical:
        line = re.sub(r"\s#.*$", "", line).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            if re.match(r"-(r|c|-requirement|-constraint)\b", line):
                lock.notes.append(f"'{line}' is not followed; scan the referenced file directly")
            continue
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        m = _REQ_PIN.match(line)
        if m and "*" not in m.group(2):
            pkg = Pkg(PYPI, _pypi_name(m.group(1)), m.group(2))
            lock.packages.add(pkg)
            lock.direct.add(pkg)
        else:
            nm = _REQ_NAME.match(line)
            unpinned.append(nm.group(1) if nm else line[:40])
    if unpinned:
        shown = ", ".join(unpinned[:8]) + (" ..." if len(unpinned) > 8 else "")
        lock.notes.append(f"{len(unpinned)} requirement(s) not pinned with == were skipped: {shown}")
    lock.notes.append("requirements.txt has no dependency graph: every pin is listed as direct")
    return lock


# ---------------------------------------------------------------- package-lock.json


def parse_package_lock(path: str, text: str) -> Lockfile:
    data = json.loads(text)
    version = data.get("lockfileVersion")
    packages: dict[str, Any] | None = data.get("packages")
    if packages is None or version not in (2, 3):
        raise LockfileError(
            f"{path}: npm lockfileVersion {version} has no flat 'packages' map. Only v2 and v3 are "
            "supported; regenerate with npm 7 or newer (`npm install --package-lock-only`)."
        )
    lock = Lockfile(path, "package-lock.json", NPM)
    nodes: dict[str, Pkg] = {}
    for key, entry in packages.items():
        if not key.startswith("node_modules/") or entry.get("link") or "version" not in entry:
            continue
        name = key.rsplit("node_modules/", 1)[1]
        # an aliased install ("foo": "npm:bar@1") records the real name in "name"
        pkg = Pkg(NPM, entry.get("name", name), entry["version"])
        nodes[key] = pkg
        lock.packages.add(pkg)

    def resolve(base: str, dep: str) -> Pkg | None:
        while True:
            hit = nodes.get(f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}")
            if hit:
                return hit
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    dep_fields = ("dependencies", "optionalDependencies")
    for key, entry in packages.items():
        if key in nodes:
            for field_name in dep_fields:
                for dep in entry.get(field_name, {}):
                    target = resolve(key, dep)
                    if target:
                        lock.add_edge(nodes[key], target)
        elif not key.startswith("node_modules/"):
            # the root project ("") or a workspace member: its deps are direct
            for field_name in (*dep_fields, "devDependencies"):
                for dep in entry.get(field_name, {}):
                    target = resolve(key, dep)
                    if target:
                        lock.direct.add(target)
    return lock


# ---------------------------------------------------------------- YAML subset (pnpm)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1].replace("''", "'") if s[0] == "'" else s[1:-1]
    return s


def _split_key(body: str) -> tuple[str, str]:
    """('key', 'rest of line') for 'key: rest' / "'quoted key': rest"."""
    if body[0] in "'\"":
        q = body[0]
        i = 1
        while i < len(body):
            if body[i] == q:
                if q == "'" and body[i + 1 : i + 2] == "'":
                    i += 2
                    continue
                break
            i += 1
        key = _unquote(body[: i + 1])
        rest = body[i + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"expected ':' after quoted key in {body[:60]!r}")
        return key, rest[1:].strip()
    idx = body.find(": ")
    if idx < 0:
        if body.endswith(":"):
            return body[:-1], ""
        raise ValueError(f"not a 'key: value' line: {body[:60]!r}")
    return body[:idx], body[idx + 2 :].strip()


def parse_yaml_map(text: str) -> dict[str, Any]:
    """The block-mapping subset of YAML that lockfiles use: nested mappings,
    scalars, block lists of scalars. Flow values ({...}, [...]) stay as raw strings."""
    root: dict[str, Any] = {}
    # stack of (indent, container, parent container, key in parent)
    stack: list[tuple[int, Any, Any, Any]] = [(-1, root, None, None)]
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        _, container, parent, pkey = stack[-1]
        if body.startswith("- ") or body == "-":
            if isinstance(container, dict) and not container and parent is not None:
                container = []
                parent[pkey] = container
                stack[-1] = (stack[-1][0], container, parent, pkey)
            if not isinstance(container, list):
                raise ValueError(f"line {lineno}: unexpected list item")
            container.append(_unquote(body[2:]))
            continue
        if not isinstance(container, dict):
            raise ValueError(f"line {lineno}: unexpected mapping inside a list")
        key, rest = _split_key(body)
        if rest == "":
            child: dict[str, Any] = {}
            container[key] = child
            stack.append((indent, child, container, key))
        else:
            container[key] = _unquote(rest)
    return root


# ---------------------------------------------------------------- pnpm-lock.yaml


def _split_name_version(spec: str) -> tuple[str, str] | None:
    """'/@scope/name@1.2.3(peer@1)' or 'name@1.2.3' -> ('@scope/name', '1.2.3')."""
    spec = spec.split("(", 1)[0].lstrip("/")
    idx = spec.rfind("@")
    if idx <= 0:
        return None
    return spec[:idx], spec[idx + 1 :]


def parse_pnpm_lock(path: str, text: str) -> Lockfile:
    doc = parse_yaml_map(text)
    raw_version = str(doc.get("lockfileVersion", "")).strip("'\"")
    try:
        major = int(raw_version.split(".")[0])
    except ValueError as e:
        raise LockfileError(f"{path}: cannot read lockfileVersion {raw_version!r}") from e
    if major < 6:
        raise LockfileError(
            f"{path}: pnpm lockfileVersion {raw_version} is older than 6.0, which is not supported. "
            "Run `pnpm install --lockfile-only` with pnpm 8 or newer to upgrade it."
        )
    lock = Lockfile(path, "pnpm-lock.yaml", NPM)

    def node(name: str, value: str) -> Pkg | None:
        """Pkg for a dependency entry: 'name' + version value (may be an alias or a link)."""
        value = value.split("(", 1)[0]
        if value.startswith(("link:", "file:", "workspace:", "git+", "http")):
            return None
        if "@" in value.lstrip("/"):  # alias: version is 'real-name@1.2.3'
            nv = _split_name_version(value)
            return Pkg(NPM, nv[0], nv[1]) if nv else None
        return Pkg(NPM, name, value.lstrip("/"))

    sections = doc.get("snapshots") or doc.get("packages") or {}
    meta = doc.get("packages") or {}
    for key in {*sections, *meta}:
        nv = _split_name_version(key)
        if nv is None:
            continue
        entry = meta.get(key)
        res = entry.get("resolution", "") if isinstance(entry, dict) else ""
        if isinstance(res, str) and ("directory:" in res or "repo:" in res):
            continue
        lock.packages.add(Pkg(NPM, nv[0], nv[1]))
    for key, entry in sections.items():
        nv = _split_name_version(key)
        if nv is None or not isinstance(entry, dict):
            continue
        src = Pkg(NPM, nv[0], nv[1])
        if src not in lock.packages:
            continue
        for field_name in ("dependencies", "optionalDependencies"):
            deps = entry.get(field_name)
            if isinstance(deps, dict):
                for dname, dver in deps.items():
                    target = node(dname, str(dver))
                    if target and target in lock.packages:
                        lock.add_edge(src, target)

    importers: dict[str, Any] = doc.get("importers") or {".": doc}
    for imp in importers.values():
        if not isinstance(imp, dict):
            continue
        for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = imp.get(field_name)
            if not isinstance(deps, dict):
                continue
            for dname, dval in deps.items():
                version = dval.get("version", "") if isinstance(dval, dict) else str(dval)  # v5-style: plain string
                target = node(dname, str(version))
                if target and target in lock.packages:
                    lock.direct.add(target)
    return lock


# ---------------------------------------------------------------- yarn.lock (v1)


def parse_yarn_lock(path: str, text: str) -> Lockfile:
    if "__metadata:" in text:
        raise LockfileError(
            f"{path} is a Yarn Berry (v2+) lockfile; only Yarn v1 is supported. "
            "Scan a package-lock.json or pnpm-lock.yaml instead, or export one."
        )
    lock = Lockfile(path, "yarn.lock", NPM)
    specs: dict[str, Pkg] = {}  # "name@range" -> locked package
    pending: list[tuple[Pkg, list[str]]] = []  # package -> dependency specs
    blocks: list[tuple[list[str], dict[str, str], list[str]]] = []  # (header specs, fields, dep specs)
    header: list[str] | None = None
    fields: dict[str, str] = {}
    deps: list[str] = []
    in_deps = False

    def flush() -> None:
        if header is not None:
            blocks.append((header, fields, deps))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        if indent == 0:
            flush()
            if not body.endswith(":"):
                raise ValueError(f"bad yarn.lock header line: {body[:60]!r}")
            header = [_unquote(s) for s in body[:-1].split(", ")]
            fields, deps, in_deps = {}, [], False
        elif indent == 2:
            if body.endswith(":"):
                in_deps = body[:-1] in ("dependencies", "optionalDependencies")
            else:
                k, _, v = body.partition(" ")
                fields[k] = _unquote(v)
                in_deps = False
        elif indent == 4 and in_deps:
            k, _, v = body.rpartition(" ")
            deps.append(f"{_unquote(k)}@{_unquote(v)}")
    flush()
    for names, flds, dep_specs in blocks:
        if "version" not in flds:
            continue
        nv = names[0].rsplit("@", 1)
        pkg = Pkg(NPM, nv[0], flds["version"])
        lock.packages.add(pkg)
        for s in names:
            specs[s] = pkg
        pending.append((pkg, dep_specs))
    for pkg, dep_specs in pending:
        for s in dep_specs:
            target = specs.get(s)
            if target:
                lock.add_edge(pkg, target)
    manifest = _read_text_if_exists(os.path.join(os.path.dirname(path), "package.json"))
    if manifest is None:
        _roots_fallback(lock, "no package.json next to yarn.lock")
    else:
        pj = json.loads(manifest)
        for f in ("dependencies", "devDependencies", "optionalDependencies"):
            for dname, rng in (pj.get(f) or {}).items():
                target = specs.get(f"{dname}@{rng}")
                if target:
                    lock.direct.add(target)
    return lock


# ---------------------------------------------------------------- Cargo.lock


def parse_cargo_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "Cargo.lock", CRATES)
    entries: list[dict[str, Any]] = data.get("package", [])
    by_name: dict[str, list[Pkg]] = {}
    audited: dict[int, Pkg] = {}
    for i, e in enumerate(entries):
        source = e.get("source", "")
        if source.startswith(("registry+", "sparse+")):
            pkg = Pkg(CRATES, e["name"], e["version"])
            audited[i] = pkg
            by_name.setdefault(pkg.name, []).append(pkg)
            lock.packages.add(pkg)

    def resolve(spec: str) -> Pkg | None:
        parts = spec.split(" ")
        candidates = by_name.get(parts[0], [])
        if len(parts) >= 2:
            return next((c for c in candidates if c.version == parts[1]), None)
        return candidates[0] if len(candidates) == 1 else None

    for i, e in enumerate(entries):
        if i in audited:
            for spec in e.get("dependencies", []):
                if (t := resolve(spec)) is not None:
                    lock.add_edge(audited[i], t)
        elif not e.get("source"):  # workspace member: what it depends on is direct
            for spec in e.get("dependencies", []):
                if (t := resolve(spec)) is not None:
                    lock.direct.add(t)
    return lock


# ---------------------------------------------------------------- go.sum


def parse_go_sum(path: str, text: str) -> Lockfile:
    lock = Lockfile(path, "go.sum", GO)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            lock.packages.add(Pkg(GO, parts[0], parts[1]))
    mod = _read_text_if_exists(os.path.join(os.path.dirname(path), "go.mod"))
    if mod is None:
        lock.direct = set(lock.packages)
        lock.notes.append("no go.mod next to go.sum: every module is listed as direct")
    else:
        direct_names: set[str] = set()
        in_block = False
        for line in mod.splitlines():
            s = line.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block and s == ")":
                in_block = False
                continue
            if in_block or s.startswith("require "):
                entry = s.removeprefix("require ").strip()
                if entry and "// indirect" not in entry and not entry.startswith("//"):
                    direct_names.add(entry.split()[0])
        lock.direct = {p for p in lock.packages if p.name in direct_names}
    lock.notes.append("go.sum has no dependency graph and can list versions that are not in the build")
    return lock


_PARSERS: dict[str, Callable[[str, str], Lockfile]] = {
    "uv.lock": parse_uv_lock,
    "poetry.lock": parse_poetry_lock,
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.sum": parse_go_sum,
}
