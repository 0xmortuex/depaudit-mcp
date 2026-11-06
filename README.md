# depaudit-mcp

**Let your AI agent audit your project's dependencies, transitive ones included, straight from the lockfiles.**

<!-- mcp-name: io.github.0xmortuex/depaudit-mcp -->

depaudit-mcp is an [MCP](https://modelcontextprotocol.io) server that reads lockfiles, asks
[OSV.dev](https://osv.dev) which locked versions have known vulnerabilities, and tells the agent
what to upgrade, how risky the upgrade is, and which direct dependency drags the problem in.
It is read-only: it never edits your lockfiles or manifests. No API key is needed.

| Lockfile | Notes |
|---|---|
| `uv.lock` | dev groups and workspace members count as direct |
| `poetry.lock` | direct deps come from the `pyproject.toml` next to it |
| `requirements.txt` (`requirements*.txt`) | `==` pins only; no graph, so every pin is "direct" |
| `package-lock.json` | v2 and v3; nested `node_modules`, workspaces, aliases |
| `pnpm-lock.yaml` | v6 to v9 |
| `yarn.lock` | Yarn v1 (Berry is rejected with a clear message) |
| `Cargo.lock` | workspace members are the roots; git/path sources are skipped |
| `go.sum` | direct modules come from `go.mod`; no dependency graph |

## What it looks like

Real output (OSV data of 2026-11-06) for an npm project that depends on `lodash 4.17.15` and `mkdirp 0.5.1`:

```
> scan_project .
depaudit scan of C:\work\demo
  package-lock.json: 35 packages, 3 direct, 32 transitive  [C:\work\demo\package-lock.json]
9 advisories across 4 vulnerable package versions: 1 CRITICAL, 4 HIGH, 3 MODERATE, 1 LOW

== package-lock.json (C:\work\demo\package-lock.json)
CRITICAL minimist 0.0.8 [transitive]  fix: upgrade to >= 0.2.4
    - GHSA-xvch-5gv4-984h (CVE-2021-44906) CRITICAL CVSS 9.8, fixed in 0.2.4: Prototype Pollution in minimist
    - GHSA-vh95-rmgr-6w4m (CVE-2020-7598) MODERATE CVSS 5.6, fixed in 0.2.1: Prototype Pollution in minimist
    via: mkdirp 0.5.1 > minimist 0.0.8
HIGH     lodash 4.17.15 [direct]  fix: upgrade to >= 4.18.0
    - GHSA-35jh-r3h4-6jhm (CVE-2021-23337) HIGH CVSS 7.2, fixed in 4.17.21: Command Injection in lodash
    ...

> suggest_fixes .
1. minimist 0.0.8 -> 0.2.4  [transitive, minor] fixes 2 advisory/ies, worst CRITICAL  BREAKING: major/0.x bump, read the changelog and run tests
     do: upgrade the parent, or add "overrides": {"minimist": "0.2.4"} to package.json
     pulled in by: mkdirp 0.5.1 > minimist 0.0.8
3. lodash 4.17.15 -> 4.18.1  [direct, minor] fixes 5 advisory/ies, worst HIGH
     do: npm install lodash@4.18.1
```

Note the lodash target: `4.18.0` is listed as the fix for one advisory, but OSV says `4.18.0`
is itself affected by another, so the plan moves on to `4.18.1`. Every proposed target is re-checked.

## Install

Needs Python 3.10+ and internet access to `api.osv.dev` and the package registries.

**Claude Code**

```bash
claude mcp add depaudit -- uvx depaudit-mcp
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "depaudit": { "command": "uvx", "args": ["depaudit-mcp"] }
  }
}
```

Without uv: `pip install depaudit-mcp`, then use `depaudit-mcp` as the command.

## Tools

| Tool | What it does |
|---|---|
| `scan_project(path, limit=30)` | Finds lockfiles under `path` (a directory, searched 3 levels deep, or one file). Counts direct vs transitive packages and lists vulnerable ones worst first, with merged advisories, CVSS, fixed-in versions and the dependency path for transitive ones. |
| `suggest_fixes(path)` | Minimal upgrade plan: the smallest version fixing every advisory (verified clean against OSV), a BREAKING flag for major and 0.x-minor bumps, the parent that pulls the package in, and the command or override to apply. Prints only; changes nothing. |
| `list_outdated(path, include_transitive=False, limit=40)` | Packages behind the latest release on PyPI, npm, crates.io or the Go proxy, labelled MAJOR / MINOR / PATCH. |
| `check_package(ecosystem, name, version)` | One name and version, no lockfile needed. Also shows the latest release. |
| `explain_vulnerability(id)` | An advisory in detail: summary, severity and vector, affected ranges, fix, references. Accepts GHSA, CVE, PYSEC, RUSTSEC, GO ids. |

## Try asking

- "Scan this project for vulnerable dependencies and tell me the three most urgent fixes."
- "Which of my vulnerable packages are transitive, and what pulls them in?"
- "What is the smallest set of upgrades that gets rid of every critical and high advisory? Which ones are breaking?"
- "Is requests 2.19.1 safe to ship? What does GHSA-x84v-xcm2-53pg actually let an attacker do?"
- "Which direct dependencies are a major version behind?"
- "Audit every lockfile in this monorepo and group the findings by service."

## How it works, and what it cannot tell you

1. Lockfiles are parsed locally into packages, direct roots and dependency edges.
2. All distinct `(ecosystem, name, version)` triples go to OSV's `/v1/querybatch` in chunks, following
   `next_page_token` until every page is read; each advisory record is then fetched once from `/v1/vulns/{id}`.
3. Records that alias each other (GHSA, PYSEC, CVE, RUSTSEC) are merged into one issue. Severity is the
   advisory's own rating, or a CVSS v3 base score computed from its vector. Records with only a CVSS v4
   vector and no rating show as UNKNOWN.
4. Latest versions come from the registries, concurrently, cached for an hour.

Limits to know about:

- It reports **published advisories for the exact locked versions**. It does not know whether your code
  calls the vulnerable function, and it finds nothing about unpublished bugs.
- Dev dependencies are included (they run in your CI). Optional and platform-specific dependencies are included
  when the lockfile lists them.
- Fixed-in versions come from OSV `ECOSYSTEM`/`SEMVER` ranges. Advisories that only list affected versions
  (no ranges) show "no fix known".
- A fix for a transitive package may be blocked by the parent's version range. The plan names the parent;
  upgrading it is usually the right move.
- `requirements.txt` has no graph (every pin shows as direct) and `go.sum` can list modules that are not in the build.
- Not supported: npm lockfile v1, pnpm before v6, Yarn Berry, pip `-r` includes (scan the included file).

## Security and privacy

- **Read-only on disk.** The server only opens lockfiles and the `package.json` / `pyproject.toml` / `go.mod`
  beside them. It never writes. `suggest_fixes` prints commands; it does not run them.
- **What leaves your machine:** package names and exact versions (to `api.osv.dev` and the registries
  `pypi.org`, `registry.npmjs.org`, `crates.io`, `proxy.golang.org`), and advisory ids. File paths and contents do
  not leave. Private package names in a lockfile are sent too, so do not point it at a lockfile whose package
  names are confidential.
- **`path` is any path the agent passes.** Like any tool that reads files, give an agent that can call it only
  the access you are comfortable with. It only parses files with the supported lockfile names.
- Requests have timeouts (20 s); 429 and 5xx responses are retried at most 3 times, honouring `Retry-After`,
  then fail with an explicit error. Lookup failures are shown, never turned into "no vulnerabilities".
- For tests or mirrors, the endpoints can be redirected with `DEPAUDIT_OSV_URL`, `DEPAUDIT_PYPI_URL`,
  `DEPAUDIT_NPM_URL`, `DEPAUDIT_CRATES_URL` and `DEPAUDIT_GOPROXY_URL`.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests            # offline: real lockfiles, a real stdio MCP session, recorded API responses
pytest tests -m live    # real OSV.dev / PyPI / npm / crates.io / Go proxy
```

The offline tests run the real HTTP client against a local server that replays responses recorded from the live
APIs (`tests/fixtures/recorded/`, produced by `tests/record_fixtures.py`), including pagination, 429 retries, timeouts
and error mapping. Lockfile fixtures for uv, poetry, npm, pnpm (v6 and v9) and Yarn v1 were generated by the real
tools; `Cargo.lock`, `go.sum` and `requirements.txt` fixtures are written by hand. The `live` tests check that
`requests 2.19.1` and `lodash 4.17.15` are reported by the real API and that proposed fix targets are clean.

## Companion

The tutorial [depaudit-mcp-the-hard-way](https://github.com/0xmortuex/depaudit-mcp-the-hard-way) builds a minimal
version of this server from scratch.

## License

MIT
