"""A small JSON-over-HTTP client with polite timeouts and retries.

Standard library only. Retries are limited to HTTP 429 and transient 5xx, honour
Retry-After, and end in a clear error: nothing is retried silently forever.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from . import __version__
from .errors import NetworkError, NotFoundError, RateLimitError

DEFAULT_URLS = {
    "osv": "https://api.osv.dev",
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
    "crates": "https://crates.io",
    "goproxy": "https://proxy.golang.org",
}


def base_url(service: str) -> str:
    """Base URL of a service; DEPAUDIT_<SERVICE>_URL overrides it (tests, mirrors)."""
    env = os.environ.get(f"DEPAUDIT_{service.upper()}_URL")
    return (env or DEFAULT_URLS[service]).rstrip("/")


class Http:
    def __init__(
        self,
        timeout: float = 20.0,
        retries: int = 3,
        max_wait: float = 10.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.max_wait = max_wait
        self._sleep = sleep

    def get_json(self, url: str) -> Any:
        return self._request(urllib.request.Request(url, method="GET"))

    def post_json(self, url: str, body: Any) -> Any:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        return self._request(req)

    def _request(self, req: urllib.request.Request) -> Any:
        req.add_header("User-Agent", f"depaudit-mcp/{__version__} (+https://github.com/0xmortuex/depaudit-mcp)")
        req.add_header("Accept", "application/json")
        url = req.full_url
        last_status = 0
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                last_status = e.code
                if e.code == 404:
                    raise NotFoundError(f"{url} answered 404 Not Found") from e
                if e.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    self._sleep(self._wait(e, attempt))
                    continue
                if e.code == 429:
                    raise RateLimitError(
                        f"{url} is rate limiting this client (HTTP 429, gave up after "
                        f"{self.retries + 1} attempts). Wait a minute and retry, or scan a smaller project."
                    ) from e
                raise NetworkError(f"{url} answered HTTP {e.code} {e.reason}") from e
            except urllib.error.URLError as e:
                raise NetworkError(
                    f"could not reach {url}: {e.reason}. Check the internet connection and any proxy settings."
                ) from e
            except TimeoutError as e:
                raise NetworkError(f"{url} did not answer within {self.timeout:g}s") from e
            except json.JSONDecodeError as e:
                raise NetworkError(f"{url} returned something that is not JSON: {e}") from e
        raise NetworkError(f"{url} kept failing (last status {last_status})")  # pragma: no cover

    def _wait(self, e: urllib.error.HTTPError, attempt: int) -> float:
        retry_after: str | None = e.headers.get("Retry-After") if e.headers else None
        if retry_after:
            try:
                return min(float(retry_after), self.max_wait)
            except ValueError:
                pass
        return min(0.5 * 2.0**attempt, self.max_wait)
