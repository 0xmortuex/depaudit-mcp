"""OSV.dev client: batched package queries (with pagination) and record lookup."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .errors import NetworkError, NotFoundError
from .http import Http, base_url
from .model import Pkg

BATCH_SIZE = 500  # OSV accepts up to 1000 queries per batch; stay well under
MAX_PAGES = 50  # safety stop for next_page_token loops
TTL = 3600.0


class OSV:
    def __init__(self, http: Http | None = None, base: str | None = None, workers: int = 8) -> None:
        self.http = http or Http()
        self._base = base
        self.workers = workers
        self._vulns: dict[str, tuple[float, dict[str, Any]]] = {}
        self._queries: dict[Pkg, tuple[float, list[str]]] = {}
        self._lock = threading.Lock()

    @property
    def base(self) -> str:
        return self._base or base_url("osv")

    def vuln_ids(self, pkgs: Iterable[Pkg]) -> dict[Pkg, list[str]]:
        """Advisory ids affecting each exact (ecosystem, name, version).
        Packages with no advisories map to []."""
        wanted = list(dict.fromkeys(pkgs))
        now = time.monotonic()
        out: dict[Pkg, list[str]] = {}
        todo: list[Pkg] = []
        for p in wanted:
            cached = self._queries.get(p)
            if cached and now - cached[0] < TTL:
                out[p] = cached[1]
            else:
                todo.append(p)
        for i in range(0, len(todo), BATCH_SIZE):
            chunk = todo[i : i + BATCH_SIZE]
            for p, ids in zip(chunk, self._query_chunk(chunk), strict=True):
                out[p] = ids
                self._queries[p] = (now, ids)
        return {p: out[p] for p in wanted}

    def _query_chunk(self, chunk: Sequence[Pkg]) -> list[list[str]]:
        url = f"{self.base}/v1/querybatch"
        ids: list[list[str]] = [[] for _ in chunk]
        # (index into chunk, page token) still to fetch; start with page one for all
        pending: list[tuple[int, str | None]] = [(i, None) for i in range(len(chunk))]
        pages = 0
        while pending:
            pages += 1
            if pages > MAX_PAGES:
                raise NetworkError(
                    f"OSV kept returning next_page_token after {MAX_PAGES} pages for a batch of "
                    f"{len(chunk)} packages; refusing to loop further"
                )
            queries = []
            for i, token in pending:
                p = chunk[i]
                q: dict[str, Any] = {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                if token:
                    q["page_token"] = token
                queries.append(q)
            resp = self.http.post_json(url, {"queries": queries})
            results = resp.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                got = len(results) if isinstance(results, list) else "no"
                raise NetworkError(f"OSV querybatch returned {got} results for {len(pending)} queries")
            nxt: list[tuple[int, str | None]] = []
            for (i, _), res in zip(pending, results, strict=True):
                ids[i].extend(v["id"] for v in res.get("vulns", []) or [])
                if res.get("next_page_token"):
                    nxt.append((i, res["next_page_token"]))
            pending = nxt
        return [list(dict.fromkeys(x)) for x in ids]

    def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Full OSV record. Raises NotFoundError for an unknown id."""
        with self._lock:
            hit = self._vulns.get(vuln_id)
        if hit and time.monotonic() - hit[0] < TTL:
            return hit[1]
        try:
            rec: dict[str, Any] = self.http.get_json(f"{self.base}/v1/vulns/{vuln_id}")
        except NotFoundError as e:
            raise NotFoundError(
                f"OSV has no record {vuln_id!r}. Use an id such as GHSA-xxxx-xxxx-xxxx, CVE-2020-1234, "
                f"PYSEC-2019-133 or RUSTSEC-2020-0071."
            ) from e
        with self._lock:
            self._vulns[vuln_id] = (time.monotonic(), rec)
        return rec

    def get_vulns(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        unique = list(dict.fromkeys(ids))
        return dict(zip(unique, pmap(self.get_vuln, unique, self.workers), strict=True))


def pmap(fn: Callable[[Any], Any], items: Sequence[Any], workers: int) -> list[Any]:
    """map() on a small thread pool, results in input order."""
    if len(items) <= 1:
        return [fn(x) for x in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(fn, items))
