"""Version comparison good enough for PEP 440, semver, Cargo and Go versions.

Not a full implementation of any of them: a release tuple of integers, then a
pre-release marker that sorts before the final release. That covers what
lockfiles pin and what advisories name as fixed versions.
"""

from __future__ import annotations

import re
from typing import Any

_HEAD = re.compile(r"^v?(?:\d+!)?(\d+(?:\.\d+)*)(.*)$", re.IGNORECASE)
_PRE_WORDS = ("a", "b", "c", "rc", "alpha", "beta", "pre", "preview", "dev")
_TOKEN = re.compile(r"\d+|[a-z]+")

VersionKey = tuple[Any, ...]


def parse(version: str) -> VersionKey | None:
    """Sortable key for a version, or None if it does not look like one
    (git hashes, 'latest', ...)."""
    m = _HEAD.match(version.strip())
    if not m:
        return None
    release = [int(x) for x in m.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = m.group(2).split("+", 1)[0].lower()  # drop build metadata
    if not rest:
        return (tuple(release), 1, ())
    tokens = _TOKEN.findall(rest)
    if tokens and tokens[0] in ("post", "p", "rev", "r"):
        # post-releases sort after the final release
        return (tuple(release), 2, tuple(_tok(t) for t in tokens))
    if rest.startswith("-") and tokens and tokens[0].isdigit():
        # PEP 440 implicit post release ("1.0-1"), or a Go pseudo-version suffix
        return (tuple(release), 2, tuple(_tok(t) for t in tokens))
    if tokens and (tokens[0] in _PRE_WORDS or rest.startswith("-")):
        return (tuple(release), 0, tuple(_tok(t) for t in tokens))
    return None


def _tok(token: str) -> tuple[int, Any]:
    # ints sort before words so "rc1" and "rc.1" compare consistently
    return (0, int(token)) if token.isdigit() else (1, token)


def compare(a: str, b: str) -> int | None:
    """-1, 0, 1, or None when either side is unparseable."""
    ka, kb = parse(a), parse(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def is_prerelease(version: str) -> bool:
    key = parse(version)
    return key is not None and key[1] == 0


def release(version: str) -> tuple[int, int, int] | None:
    key = parse(version)
    if key is None:
        return None
    r = list(key[0])[:3]
    while len(r) < 3:
        r.append(0)
    return (r[0], r[1], r[2])


def bump_kind(installed: str, target: str) -> str | None:
    """'major', 'minor' or 'patch' for the size of the jump installed -> target;
    None if target is not newer or either is unparseable."""
    c = compare(installed, target)
    ri, rt = release(installed), release(target)
    if c is None or c >= 0 or ri is None or rt is None:
        return None
    if rt[0] != ri[0]:
        return "major"
    if rt[1] != ri[1]:
        return "minor"
    return "patch"


def is_breaking(installed: str, target: str) -> bool:
    """A major bump, or a minor bump on a 0.x version (semver treats 0.y as
    unstable: any minor change may break)."""
    kind = bump_kind(installed, target)
    if kind == "major":
        return True
    ri = release(installed)
    return kind == "minor" and ri is not None and ri[0] == 0
