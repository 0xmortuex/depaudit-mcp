"""Re-record tests/fixtures/recorded/ from the LIVE OSV.dev / registry APIs.

    uv run python tests/record_fixtures.py

Runs the real tools over every project in tests/fixtures/ while a recording
wrapper sits on the HTTP client, and stores each exchange: OSV per-package
query results, OSV records (verbatim), and the latest version per package
(registry responses are reduced to that one field). The offline tests replay
this data through a local HTTP server (tests/fakeapis.py), so CI needs no
network. Re-record to refresh advisories; tests assert on stable facts
(a pinned vulnerable version is reported) rather than exact counts.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
import urllib.parse
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
OUT = os.path.join(FIX, "recorded")

from depaudit_mcp import server  # noqa: E402
from depaudit_mcp.http import Http, base_url  # noqa: E402


class Recorder(Http):
    def __init__(self) -> None:
        super().__init__()
        self.queries: dict[str, list[dict[str, Any]]] = {}
        self.vulns: dict[str, Any] = {}
        self.latest: dict[str, str] = {}

    def post_json(self, url: str, body: Any) -> Any:
        resp = super().post_json(url, body)
        for q, res in zip(body["queries"], resp["results"], strict=True):
            key = f"{q['package']['ecosystem']}|{q['package']['name']}|{q['version']}"
            self.queries.setdefault(key, [])
            self.queries[key] += res.get("vulns", [])
            if res.get("next_page_token"):
                raise SystemExit("OSV paginated during recording; extend the recorder")
        return resp

    def get_json(self, url: str) -> Any:
        data = super().get_json(url)
        path = urllib.parse.urlparse(url).path
        if url.startswith(base_url("osv")):
            self.vulns[path.rsplit("/", 1)[1]] = data
        elif url.startswith(base_url("pypi")):
            self.latest["PyPI|" + path.split("/")[2]] = data["info"]["version"]
        elif url.startswith(base_url("npm")):
            name = urllib.parse.unquote(path[1:].rsplit("/latest", 1)[0])
            self.latest["npm|" + name] = data["version"]
        elif url.startswith(base_url("crates")):
            c = data["crate"]
            self.latest["crates.io|" + c["id"]] = c.get("max_stable_version") or c["max_version"]
        elif url.startswith(base_url("goproxy")):
            mod = path[1:].rsplit("/@latest", 1)[0]
            self.latest["Go|" + mod] = data["Version"]
        return data


def main() -> None:
    rec = Recorder()
    server._osv.http = rec
    server._registry.http = rec
    for name in sorted(os.listdir(FIX)):
        d = os.path.join(FIX, name)
        if name == "recorded" or not os.path.isdir(d):
            continue
        print("recording", name, file=sys.stderr)
        server.scan_project(d)
        server.suggest_fixes(d)
        server.list_outdated(d, include_transitive=(name == "uv"))
    server.check_package("PyPI", "requests", "2.19.1")
    server.check_package("npm", "lodash", "4.17.15")
    server.check_package("PyPI", "requests", "2.34.2")
    for vid in ("GHSA-x84v-xcm2-53pg", "CVE-2018-18074", "PYSEC-2018-28"):
        server.explain_vulnerability(vid)
    os.makedirs(OUT, exist_ok=True)
    meta = {"recorded": datetime.date.today().isoformat(), "source": "api.osv.dev + pypi/npm/crates.io/goproxy"}
    for fname, data in (("osv_query.json", rec.queries), ("osv_vulns.json", rec.vulns), ("latest.json", rec.latest),
                        ("meta.json", meta)):
        with open(os.path.join(OUT, fname), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(f"recorded {len(rec.queries)} queries, {len(rec.vulns)} vulns, {len(rec.latest)} latest versions", file=sys.stderr)


if __name__ == "__main__":
    main()
