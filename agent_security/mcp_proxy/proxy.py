"""MCP plumbing for the proxy.

Facing the agent, the proxy is an MCP *server* over stdio. Facing the real
server, it is an MCP *client* that launches the upstream command as a
subprocess over stdio. ``build_server`` connects the two through the
``SecurityPipeline``; everything it does to a message is decided there.

stdout is the protocol channel, so the proxy only ever logs to stderr (and the
upstream server's stderr is passed through to ours).
"""
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from mcp import Client, MCPError, StdioServerParameters, types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .gateway_client import GatewayClient
from .pinning import PinStore
from .pipeline import STATUS_OK, ResultWithheld, SecurityPipeline, ToolDef
from .policy import ProxyPolicy

logger = logging.getLogger("mcp_proxy")

PROXY_NAME = "mcp-security-proxy"
DEFAULT_PINS_PATH = Path(__file__).resolve().parent / "state" / "pins.json"
# never handed to the upstream server: it is the proxy's credential for the gateway
SECRET_ENV_VARS = ("MCP_PROXY_TOKEN",)
NON_TEXT_NOTICE = "[non-text content removed by the security proxy]"


class ConfigError(ValueError):
    """The proxy's environment configuration is unusable."""


@dataclass(frozen=True)
class ProxyConfig:
    policy: ProxyPolicy
    upstream: list
    gateway_url: str
    token: str
    pins_path: Path
    poll_interval: float = 2.0


def config_from_env(policy: ProxyPolicy, upstream, env=None) -> ProxyConfig:
    """Read GATEWAY_URL, MCP_PROXY_TOKEN, MCP_PINS_PATH, MCP_APPROVAL_POLL_SECONDS."""
    env = os.environ if env is None else env
    token = env.get("MCP_PROXY_TOKEN", "")
    if not token:
        raise ConfigError("MCP_PROXY_TOKEN is not set: the proxy cannot authenticate to the gateway")
    if not upstream:
        raise ConfigError("no upstream command given (use: python -m mcp_proxy --policy FILE -- COMMAND ...)")
    try:
        poll = float(env.get("MCP_APPROVAL_POLL_SECONDS", "2"))
    except ValueError:
        raise ConfigError("MCP_APPROVAL_POLL_SECONDS must be a number") from None
    if poll <= 0:
        raise ConfigError("MCP_APPROVAL_POLL_SECONDS must be positive")
    return ProxyConfig(
        policy=policy,
        upstream=list(upstream),
        gateway_url=env.get("GATEWAY_URL") or "http://localhost:8000",
        token=token,
        pins_path=Path(env.get("MCP_PINS_PATH") or DEFAULT_PINS_PATH),
        poll_interval=poll,
    )


def upstream_environment(env=None) -> dict:
    """The environment the upstream server gets: ours, minus the proxy's secrets."""
    env = os.environ if env is None else env
    return {key: value for key, value in env.items() if key not in SECRET_ENV_VARS}


def to_def(tool) -> ToolDef:
    return ToolDef(tool.name, tool.description, tool.input_schema)


async def fetch_tools(upstream) -> list:
    """A fresh, complete tool list from the upstream server (all pages)."""
    tools, cursor = [], None
    while True:
        page = await upstream.list_tools(cursor=cursor, cache_mode="bypass")
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=message)], is_error=True)


async def _scan_result(pipeline: SecurityPipeline, name: str, result):
    """The upstream result with every text block redacted and sanitized.

    Non-text blocks cannot be scanned, so they are replaced by a notice, and
    ``structured_content`` is dropped (it would carry the same data past the scan).
    """
    blocks = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            blocks.append(types.TextContent(text=await pipeline.sanitize_result(name, block.text)))
        else:
            blocks.append(types.TextContent(text=NON_TEXT_NOTICE))
    return types.CallToolResult(content=blocks, is_error=result.is_error)


def build_server(pipeline: SecurityPipeline, upstream) -> Server:
    """The agent-facing server. ``upstream`` is an ``mcp.Client`` for the real server."""
    policy = pipeline.policy

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        try:
            tools = await fetch_tools(upstream)
        except Exception as exc:  # noqa: BLE001
            logger.error("upstream tools/list failed: %s", type(exc).__name__)
            raise MCPError(types.INTERNAL_ERROR, "the upstream MCP server did not answer") from None
        statuses = await pipeline.review_tools([to_def(tool) for tool in tools])
        visible = []
        for tool in tools:
            if statuses.get(tool.name) != STATUS_OK:
                continue
            if policy.tool(tool.name).scan_results:
                # results are rewritten as plain text, so a structured output schema would not hold
                tool = tool.model_copy(update={"output_schema": None})
            visible.append(tool)
        return types.ListToolsResult(tools=visible)

    async def on_call_tool(ctx, params) -> types.CallToolResult:
        name = params.name
        try:
            definitions = [to_def(tool) for tool in await fetch_tools(upstream)]
        except Exception as exc:  # noqa: BLE001
            logger.error("upstream tools/list failed before a call: %s", type(exc).__name__)
            return _error(f"Tool {name!r} was not called: the upstream MCP server did not answer.")

        decision = await pipeline.authorize_call(name, params.arguments, definitions)
        if not decision.allowed:
            return _error(decision.message)

        try:
            result = await upstream.call_tool(name, decision.args)
        except Exception as exc:  # noqa: BLE001
            logger.error("upstream call to %s failed: %s", name, type(exc).__name__)
            return _error(f"Tool {name!r} failed: the upstream MCP server returned an error ({type(exc).__name__}).")

        if not policy.tool(name).scan_results:
            return result
        try:
            return await _scan_result(pipeline, name, result)
        except ResultWithheld as exc:
            return _error(str(exc))

    return Server(PROXY_NAME, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def run_proxy(config: ProxyConfig) -> None:  # pragma: no cover - runs only as a subprocess (see test_e2e_stdio)
    """Serve the agent on stdin/stdout until it disconnects.

    It takes over this process's stdin/stdout, so it is exercised by the stdio
    end-to-end tests, which run it in a child process that coverage does not see.
    """
    gateway = GatewayClient(config.gateway_url, config.token)
    pipeline = SecurityPipeline(
        config.policy, gateway, PinStore(config.pins_path), poll_interval=config.poll_interval
    )
    params = StdioServerParameters(
        command=config.upstream[0],
        args=config.upstream[1:],
        env=upstream_environment(),
    )
    try:
        async with Client(params) as upstream:
            server = build_server(pipeline, upstream)
            async with stdio_server() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        await gateway.aclose()
