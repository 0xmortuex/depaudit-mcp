"""Latest-version lookups against the package registries, concurrent and cached."""

from __future__ import annotations

import re
import threading
import time
import urllib.parse
from collections.abc import Iterable
from typing import Any

from .errors import DepauditError, NetworkError
from .http import Http, base_url
from .model import CRATES, GO, NPM, PYPI, Pkg
from .osv import TTL, pmap


def pypi_normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _go_escape(path: str) -> str:
    # the module proxy protocol writes uppercase letters as !lowercase
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


class Registry:
    def __init__(self, http: Http | None = None, workers: int = 8) -> None:
        self.http = http or Http()
        self.workers = workers
        self._cache: dict[tuple[str, str], tuple[float, str]] = {}
        self._lock = threading.Lock()

    def latest(self, ecosystem: str, name: str) -> str:
        key = (ecosystem, name)
        with self._lock:
            hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < TTL:
            return hit[1]
        version = self._fetch(ecosystem, name)
        with self._lock:
            self._cache[key] = (time.monotonic(), version)
        return version

    def _fetch(self, ecosystem: str, name: str) -> str:
        data: Any
        if ecosystem == PYPI:
            data = self.http.get_json(f"{base_url('pypi')}/pypi/{pypi_normalize(name)}/json")
            return str(data["info"]["version"])
        if ecosystem == NPM:
            data = self.http.get_json(f"{base_url('npm')}/{urllib.parse.quote(name, safe='@')}/latest")
            return str(data["version"])
        if ecosystem == CRATES:
            data = self.http.get_json(f"{base_url('crates')}/api/v1/crates/{name}")
            crate = data["crate"]
            return str(crate.get("max_stable_version") or crate["max_version"])
        if ecosystem == GO:
            data = self.http.get_json(f"{base_url('goproxy')}/{_go_escape(name)}/@latest")
            return str(data["Version"])
        raise DepauditError(f"no registry known for ecosystem {ecosystem!r}")

    def latest_many(self, pkgs: Iterable[Pkg]) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
        """(latest versions, error messages) keyed by (ecosystem, name). A package
        whose lookup failed appears in the second dict, never silently dropped."""
        keys = list(dict.fromkeys((p.ecosystem, p.name) for p in pkgs))

        def one(key: tuple[str, str]) -> tuple[str | None, str | None]:
            try:
                return self.latest(*key), None
            except (NetworkError, KeyError, TypeError) as e:
                return None, f"{type(e).__name__}: {e}"

        found: dict[tuple[str, str], str] = {}
        failed: dict[tuple[str, str], str] = {}
        for key, (ver, err) in zip(keys, pmap(one, keys, self.workers), strict=True):
            if ver is not None:
                found[key] = ver
            else:
                failed[key] = err or "unknown error"
        return found, failed
