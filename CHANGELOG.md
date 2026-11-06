# Changelog

## 0.1.0 - 2026-11-06

First release.

- Lockfile parsers, written by hand: `uv.lock`, `poetry.lock`, `requirements*.txt` (`==` pins),
  `package-lock.json` (v2/v3, nested `node_modules` resolution, workspaces, aliases),
  `pnpm-lock.yaml` (v6-v9), `yarn.lock` (v1), `Cargo.lock`, `go.sum` (+ `go.mod` for direct).
- Tools: `scan_project`, `check_package`, `list_outdated`, `explain_vulnerability`, `suggest_fixes`.
- Vulnerabilities from OSV.dev: batched queries with `next_page_token` pagination, concurrent
  record fetches, in-memory caching, aliases (GHSA/PYSEC/CVE/RUSTSEC/GO) merged into one issue,
  severity from the advisory or a CVSS v3 score computed from its vector.
- Dependency paths: the shortest chain from a direct dependency to each vulnerable transitive package.
- Outdated checks against PyPI, the npm registry, crates.io and the Go module proxy.
- Fix plans verify that the proposed version is not itself vulnerable, flag major (and 0.x minor)
  bumps, and never modify files.
- 429 and transient 5xx responses are retried with `Retry-After`, then reported as a clear error.
