"""A local HTTP server that replays tests/fixtures/recorded/ with the same
paths and JSON shapes as OSV.dev, PyPI, npm, crates.io and the Go module proxy.

The real HTTP client talks to it over a real socket, so URL building, JSON
handling, pagination, retries and error mapping are all exercised for real.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "recorded")


def _load(name: str) -> Any:
    with open(os.path.join(REC, name), encoding="utf-8") as fh:
        return json.load(fh)


class FakeAPIs:
    def __init__(self) -> None:
        self.queries: dict[str, list[dict[str, Any]]] = _load("osv_query.json")
        self.vulns: dict[str, Any] = _load("osv_vulns.json")
        self.latest: dict[str, str] = _load("latest.json")
        self.page_size = 0  # >0: paginate querybatch results with next_page_token
        self.fail_next: list[tuple[int, str | None]] = []  # (status, Retry-After) served before real answers
        self.delay = 0.0
        self.garbage = False  # answer 200 with non-JSON
        self.calls: list[tuple[str, str]] = []
        self.unrecorded: list[str] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:  # silence
                pass

            def _send(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _common(self, method: str) -> bool:
                with outer._lock:
                    outer.calls.append((method, self.path))
                    failing = outer.fail_next.pop(0) if outer.fail_next else None
                if outer.delay:
                    time.sleep(outer.delay)
                if failing:
                    status, retry_after = failing
                    self._send(status, {"error": "injected"}, {"Retry-After": retry_after} if retry_after else None)
                    return True
                if outer.garbage:
                    self._send(200, b"<html>not json</html>")
                    return True
                return False

            def do_GET(self) -> None:
                if self._common("GET"):
                    return
                path = urllib.parse.unquote(urllib.parse.urlparse(self.path).path)
                r = outer.route_get(path)
                if r is None:
                    self._send(404, {"code": 5, "message": "Not Found"})
                else:
                    self._send(200, r)

            def do_POST(self) -> None:
                if self._common("POST"):
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path != "/v1/querybatch":
                    self._send(404, {"message": "Not Found"})
                    return
                self._send(200, outer.querybatch(body))

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request: Any, client_address: Any) -> None:  # client hung up (timeout tests)
                pass

        self.server = Quiet(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> FakeAPIs:
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def env(self) -> dict[str, str]:
        return {f"DEPAUDIT_{s}_URL": self.url for s in ("OSV", "PYPI", "NPM", "CRATES", "GOPROXY")}

    def route_get(self, path: str) -> Any:
        if path.startswith("/v1/vulns/"):
            return self.vulns.get(path.rsplit("/", 1)[1])
        if path.startswith("/pypi/") and path.endswith("/json"):
            v = self.latest.get("PyPI|" + path.split("/")[2])
            return {"info": {"version": v}} if v else None
        if path.endswith("/latest"):
            v = self.latest.get("npm|" + path[1:-len("/latest")])
            return {"version": v} if v else None
        if path.startswith("/api/v1/crates/"):
            name = path.rsplit("/", 1)[1]
            v = self.latest.get("crates.io|" + name)
            return {"crate": {"id": name, "max_stable_version": v, "max_version": v}} if v else None
        if path.endswith("/@latest"):
            mod = path[1:-len("/@latest")]
            mod = re.sub(r"!([a-z])", lambda m: m.group(1).upper(), mod)
            v = self.latest.get("Go|" + mod)
            return {"Version": v} if v else None
        return None

    def querybatch(self, body: dict[str, Any]) -> dict[str, Any]:
        results = []
        for q in body["queries"]:
            key = f"{q['package']['ecosystem']}|{q['package']['name']}|{q['version']}"
            if key not in self.queries:
                self.unrecorded.append(key)
            vulns = self.queries.get(key, [])
            if self.page_size:
                start = int(q.get("page_token", 0))
                page = vulns[start : start + self.page_size]
                res: dict[str, Any] = {"vulns": page} if page else {}
                if start + self.page_size < len(vulns):
                    res["next_page_token"] = str(start + self.page_size)
                results.append(res)
            else:
                results.append({"vulns": vulns} if vulns else {})
        return {"results": results}
