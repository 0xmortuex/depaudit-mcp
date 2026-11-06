"""MCP stdio smoke test: spawns the real server as a subprocess over stdio, lists the
tools and calls them. OSV/registry traffic goes to a local server replaying recorded
responses (via the DEPAUDIT_*_URL variables), so no internet is needed.
MCPServer hides any exception that isn't a ToolError, so this also checks that
instructive errors survive the trip to the agent."""

import os
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {"scan_project", "check_package", "list_outdated", "explain_vulnerability", "suggest_fixes"}
FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def params(fake):
    env = {**os.environ, **fake.env()}
    return StdioServerParameters(command=sys.executable, args=["-m", "depaudit_mcp"], env=env)


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio(fake):
    async with stdio_client(params(fake)) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "depaudit"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(t.description and len(t.description) > 80 for t in tools)

        res = await session.call_tool("scan_project", {"path": os.path.join(FIX, "npm")})
        assert not res.is_error
        text = res.content[0].text
        assert "lodash 4.17.15 [direct]" in text and "via: mkdirp 0.5.1 > minimist 0.0.8" in text

        res = await session.call_tool("check_package", {"ecosystem": "PyPI", "name": "requests", "version": "2.19.1"})
        assert not res.is_error and "GHSA-x84v-xcm2-53pg" in res.content[0].text

        res = await session.call_tool("suggest_fixes", {"path": os.path.join(FIX, "uv")})
        assert not res.is_error and "read-only" in res.content[0].text

        res = await session.call_tool("list_outdated", {"path": os.path.join(FIX, "pnpm9")})
        assert not res.is_error and "MAJOR mkdirp" in res.content[0].text

        res = await session.call_tool("explain_vulnerability", {"id": "GHSA-x84v-xcm2-53pg"})
        assert not res.is_error and "fixed in 2.20.0" in res.content[0].text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(fake, tmp_path):
    async with stdio_client(params(fake)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("scan_project", {"path": str(tmp_path)})
        assert res.is_error and "no lockfile found" in res.content[0].text and "uv lock" in res.content[0].text
        res = await session.call_tool("scan_project", {"path": str(tmp_path / "missing")})
        assert res.is_error and "does not exist" in res.content[0].text
        res = await session.call_tool("check_package", {"ecosystem": "maven", "name": "x", "version": "1"})
        assert res.is_error and "unknown ecosystem" in res.content[0].text
        res = await session.call_tool("explain_vulnerability", {"id": "GHSA-nope"})
        assert res.is_error and "OSV has no record" in res.content[0].text


@pytest.mark.anyio
async def test_rate_limit_is_a_clear_tool_error(fake):
    fake.fail_next = [(429, "0")] * 20
    async with stdio_client(params(fake)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("check_package", {"ecosystem": "PyPI", "name": "requests", "version": "2.19.1"})
        assert res.is_error and "rate limiting" in res.content[0].text and "HTTP 429" in res.content[0].text
