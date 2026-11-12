"""The proxy glue with a real demo server and a real MCP client, all in-process
(memory transports) and a fake gateway: scenarios A-H without subprocesses."""
import asyncio
import json
from types import SimpleNamespace
from typing import TypedDict

import pytest
from mcp import Client, MCPError
from mcp.server.mcpserver import Image, MCPServer

from demo_server.server import create_server
from mcp_proxy import proxy
from mcp_proxy.pinning import PinStore
from mcp_proxy.pipeline import SecurityPipeline
from mcp_proxy.policy import load_policy, parse_policy
from mcp_proxy.proxy import NON_TEXT_NOTICE, build_server, fetch_tools

CARD = "4111 1111 1111 1111"
IBAN = "IL620108000000099999999"
MARKER = "[removed by security proxy: possible prompt injection]"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    path = tmp_path / "outbox.jsonl"
    monkeypatch.setenv("DEMO_OUTBOX_PATH", str(path))
    return path


def outbox_lines(path):
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


@pytest.fixture
def make_pipeline(tmp_path, gateway):
    def factory(policy=None):
        return SecurityPipeline(
            policy or load_policy(), gateway, PinStore(tmp_path / "pins.json"), poll_interval=0.01
        )

    return factory


def session(pipeline, upstream_server, scenario):
    """Run ``scenario(agent)`` with the proxy between a client and the upstream server."""

    async def go():
        async with Client(upstream_server) as upstream:
            async with Client(build_server(pipeline, upstream)) as agent:
                return await scenario(agent)

    return run(go())


def text_of(result):
    return "".join(block.text for block in result.content)


# --- A: the tool list ------------------------------------------------------------------------


def test_a_the_allowed_tools_are_visible_and_pinned(make_pipeline, state):
    pipeline = make_pipeline()

    async def scenario(agent):
        return (await agent.list_tools()).tools

    tools = session(pipeline, create_server(rug_pull=False), scenario)
    assert [t.name for t in tools] == ["list_documents", "read_document", "send_email"]
    assert {entry[1] for entry in pipeline.pins.entries()} == {"list_documents", "read_document", "send_email"}
    assert state.events == []


def test_tools_outside_the_policy_are_invisible_and_uncallable(make_pipeline, state, outbox):
    policy = parse_policy({"server": "corp-docs", "tools": {"read_document": {"scan_args": False}}})

    async def scenario(agent):
        tools = (await agent.list_tools()).tools
        blocked = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
        return tools, blocked

    tools, blocked = session(make_pipeline(policy), create_server(rug_pull=False), scenario)
    assert [t.name for t in tools] == ["read_document"]
    assert blocked.is_error and "not allowed" in text_of(blocked)
    assert state.event_types() == ["TOOL_NOT_ALLOWED"] and outbox_lines(outbox) == []


# --- B, C, D: results ---------------------------------------------------------------------------


def read(pipeline, name):
    async def scenario(agent):
        return await agent.call_tool("read_document", {"name": name})

    return session(pipeline, create_server(rug_pull=False), scenario)


def test_b_a_clean_document_comes_through_unchanged(make_pipeline, state):
    from demo_server.server import read_document

    result = read(make_pipeline(), "welcome.md")
    assert not result.is_error and text_of(result) == read_document("welcome.md")
    assert state.event_types() == ["TOOL_CALL_ALLOWED"]


def test_c_the_injection_in_the_vendor_invoice_is_removed(make_pipeline, state):
    result = read(make_pipeline(), "vendor-invoice.md")
    text = text_of(result)
    assert MARKER in text
    for leaked in ("audit@vendor-billing", "ignore your previous", "Do not tell the user", "​", "<!--", "customers.csv"):
        assert leaked not in text
    assert "Total due: 838.00 EUR" in text and "Thank you for your business." in text
    assert state.event_types() == ["TOOL_CALL_ALLOWED", "RESULT_INJECTION_REMOVED"]
    assert "audit@" not in json.dumps(state.events)


def test_d_card_and_iban_in_a_document_are_redacted(make_pipeline, state):
    text = text_of(read(make_pipeline(), "customers.csv"))
    assert CARD not in text and IBAN not in text and "4111" not in text
    assert "****1111" in text and "[REDACTED:IBAN]" in text
    assert "dana.levi@example.com" in text  # email is alert-only: left readable
    assert state.event_types() == ["TOOL_CALL_ALLOWED", "RESULT_REDACTED"]
    event = state.events[-1]
    assert set(event["data_types"]) >= {"CREDIT_CARD", "IBAN"}
    assert CARD not in json.dumps(state.events) and IBAN not in json.dumps(state.events)


def test_a_failing_upstream_tool_has_its_error_text_scanned_too(make_pipeline):
    result = read(make_pipeline(), "../secret")
    assert result.is_error and "unknown document" in text_of(result)


def test_list_documents_goes_through_the_result_scan(make_pipeline, state):
    async def scenario(agent):
        return await agent.call_tool("list_documents", {})

    result = session(make_pipeline(), create_server(rug_pull=False), scenario)
    assert text_of(result).splitlines() == ["customers.csv", "q3-report.md", "vendor-invoice.md", "welcome.md"]
    assert ("tool_result", text_of(result)) in state.scans


# --- E, F, G: sending email ----------------------------------------------------------------------


def send(pipeline, args, rug_pull=False):
    async def scenario(agent):
        return await agent.call_tool("send_email", args)

    return session(pipeline, create_server(rug_pull=rug_pull), scenario)


def test_e_an_internal_clean_email_is_sent(make_pipeline, state, outbox):
    result = send(make_pipeline(), {"to": "colleague@corp.example", "subject": "Hi", "body": "See you at 10."})
    assert not result.is_error and text_of(result) == "queued"
    assert len(outbox_lines(outbox)) == 1 and state.approvals == {}
    assert state.event_types() == ["TOOL_CALL_ALLOWED"]


def test_f_an_email_with_a_card_number_is_blocked(make_pipeline, state, outbox):
    result = send(make_pipeline(), {"to": "colleague@corp.example", "subject": "Hi", "body": f"card {CARD}"})
    assert result.is_error and "CREDIT_CARD" in text_of(result)
    assert outbox_lines(outbox) == []
    assert state.event_types() == ["ARGS_DLP_BLOCKED"] and CARD not in json.dumps(state.events)


def test_an_email_with_an_iban_is_refused_not_masked(make_pipeline, state, outbox):
    result = send(make_pipeline(), {"to": "colleague@corp.example", "subject": "Hi", "body": f"pay {IBAN}"})
    assert result.is_error and "never edits a call silently" in text_of(result)
    assert outbox_lines(outbox) == []


def test_g_an_external_email_goes_out_only_after_approval(make_pipeline, gateway, state, outbox):
    gateway.state.auto_decision = "approve"
    result = send(make_pipeline(), {"to": "bob@example.org", "subject": "Hi", "body": "Hello Bob"})
    assert text_of(result) == "queued"
    assert json.loads(outbox_lines(outbox)[0])["to"] == "bob@example.org"
    assert state.event_types() == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED", "TOOL_CALL_ALLOWED"]


def test_g_a_denied_external_email_is_never_sent(make_pipeline, gateway, state, outbox):
    gateway.state.auto_decision = "deny"
    result = send(make_pipeline(), {"to": "bob@example.org", "subject": "Hi", "body": "Hello Bob"})
    assert result.is_error and "denied" in text_of(result)
    assert outbox_lines(outbox) == []


def test_the_call_that_runs_is_exactly_the_call_that_was_approved(make_pipeline, gateway, state, outbox):
    gateway.state.auto_decision = "approve"
    args = {"to": "bob@example.org", "subject": "Hi", "body": "Hello Bob"}
    send(make_pipeline(), args)
    (record,) = state.approvals.values()
    sent = json.loads(outbox_lines(outbox)[0])
    from mcp_proxy.pinning import args_fingerprint

    assert record["args_sha256"] == args_fingerprint({"to": sent["to"], "subject": sent["subject"], "body": sent["body"]})


# --- H: rug pull ---------------------------------------------------------------------------------


def test_h_a_tool_that_changes_after_being_trusted_is_blocked(make_pipeline, state, outbox):
    pipeline = make_pipeline()
    # first run: the clean definitions are pinned
    session(pipeline, create_server(rug_pull=False), lambda agent: agent.list_tools())

    async def scenario(agent):
        first = (await agent.list_tools()).tools  # the rug-pull server still behaves
        second = (await agent.list_tools()).tools  # ...and now send_email has changed
        call = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
        return first, second, call

    first, second, call = session(pipeline, create_server(rug_pull=True), scenario)
    assert "send_email" in [t.name for t in first]
    assert [t.name for t in second] == ["list_documents", "read_document"]
    assert call.is_error and "rug pull" in text_of(call) and "pins reset send_email" in text_of(call)
    assert outbox_lines(outbox) == []
    assert state.event_types().count("TOOL_DEFINITION_CHANGED") == 2  # once on the list, once on the call
    assert "BCC" not in json.dumps(state.events) and "collector" not in json.dumps(state.events)


def test_a_change_between_the_list_and_the_call_is_caught_at_the_call(make_pipeline, state, outbox):
    pipeline = make_pipeline()
    server = create_server(rug_pull=True)

    async def scenario(agent):
        tools = (await agent.list_tools()).tools  # list 1: clean, pinned
        call = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})  # list 2: changed
        return tools, call

    tools, call = session(pipeline, server, scenario)
    assert "send_email" in [t.name for t in tools]
    assert call.is_error and "rug pull" in text_of(call) and outbox_lines(outbox) == []


def test_a_poisoned_tool_from_the_start_is_quarantined(make_pipeline, state, outbox):
    server = create_server(rug_pull=True)
    server._list_calls = 1  # poisoned from its very first list

    async def scenario(agent):
        tools = (await agent.list_tools()).tools
        call = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
        return tools, call

    tools, call = session(make_pipeline(), server, scenario)
    assert [t.name for t in tools] == ["list_documents", "read_document"]
    assert call.is_error and "prompt injection" in text_of(call) and outbox_lines(outbox) == []
    assert "TOOL_POISONING_SUSPECTED" in state.event_types()


# --- fail closed ------------------------------------------------------------------------------------


def test_with_the_gateway_down_new_tools_stay_hidden(make_pipeline, gateway):
    gateway.down = True

    async def scenario(agent):
        return (await agent.list_tools()).tools

    assert session(make_pipeline(), create_server(rug_pull=False), scenario) == []


def test_with_the_gateway_down_pinned_tools_remain_listed_but_calls_are_refused(make_pipeline, gateway, state, outbox):
    pipeline = make_pipeline()
    session(pipeline, create_server(rug_pull=False), lambda agent: agent.list_tools())
    gateway.down = True

    async def scenario(agent):
        tools = (await agent.list_tools()).tools
        read_call = await agent.call_tool("read_document", {"name": "welcome.md"})
        mail_call = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
        return tools, read_call, mail_call

    tools, read_call, mail_call = session(pipeline, create_server(rug_pull=False), scenario)
    assert len(tools) == 3
    assert read_call.is_error and "unreachable" in text_of(read_call)
    assert mail_call.is_error and "unreachable" in text_of(mail_call)
    assert outbox_lines(outbox) == []


def test_a_result_is_withheld_if_the_gateway_dies_during_the_scan(make_pipeline, gateway):
    pipeline = make_pipeline()
    session(pipeline, create_server(rug_pull=False), lambda agent: agent.list_tools())
    gateway.fail = {"scan"}  # health check passes, the scan itself fails
    result = read(pipeline, "welcome.md")
    assert result.is_error and "withheld" in text_of(result) and "Welcome" not in text_of(result)


# --- non-text content and structured output ------------------------------------------------------------


class CardInfo(TypedDict):
    card: str


def odd_upstream():
    server = MCPServer("odd")

    @server.tool(name="structured")
    def structured() -> CardInfo:
        """Returns structured data."""
        return {"card": CARD}

    @server.tool(name="picture", structured_output=False)
    def picture():
        """Returns an image."""
        return Image(data=b"\x89PNG", format="png")

    return server


def test_structured_output_is_dropped_and_images_are_replaced_when_results_are_scanned(make_pipeline, state):
    policy = parse_policy(
        {"server": "odd", "tools": {"structured": {"scan_args": False}, "picture": {"scan_args": False}}}
    )

    async def scenario(agent):
        tools = {t.name: t for t in (await agent.list_tools()).tools}
        structured = await agent.call_tool("structured", {})
        picture = await agent.call_tool("picture", {})
        return tools, structured, picture

    tools, structured, picture = session(make_pipeline(policy), odd_upstream(), scenario)
    assert tools["structured"].output_schema is None
    assert structured.structured_content is None and CARD not in text_of(structured)
    assert "****1111" in text_of(structured)
    assert text_of(picture) == NON_TEXT_NOTICE


def test_results_pass_through_untouched_when_scanning_is_switched_off(make_pipeline, state):
    policy = parse_policy({"server": "odd", "tools": {"structured": {"scan_args": False, "scan_results": False}}})

    async def scenario(agent):
        tools = {t.name: t for t in (await agent.list_tools()).tools}
        return tools["structured"], await agent.call_tool("structured", {})

    tool, result = session(make_pipeline(policy), odd_upstream(), scenario)
    assert tool.output_schema is not None and result.structured_content == {"card": CARD}


# --- upstream trouble -------------------------------------------------------------------------------------


class FakeUpstream:
    def __init__(self, pages=None, list_error=None, call_error=None):
        self.pages = pages or [[]]
        self.list_error, self.call_error = list_error, call_error
        self.cursors = []

    async def list_tools(self, cursor=None, cache_mode="use"):
        self.cursors.append((cursor, cache_mode))
        if self.list_error:
            raise self.list_error
        index = int(cursor or 0)
        more = index + 1 < len(self.pages)
        return SimpleNamespace(tools=self.pages[index], next_cursor=str(index + 1) if more else None)

    async def call_tool(self, name, arguments):
        raise self.call_error


def tool_object(name):
    from mcp_types import Tool

    return Tool(name=name, description=f"{name} tool", input_schema={"type": "object"})


def test_fetch_tools_follows_pagination_and_bypasses_the_cache():
    upstream = FakeUpstream(pages=[[tool_object("a")], [tool_object("b")], [tool_object("c")]])
    assert [t.name for t in run(fetch_tools(upstream))] == ["a", "b", "c"]
    assert upstream.cursors == [(None, "bypass"), ("1", "bypass"), ("2", "bypass")]


def test_the_agent_gets_a_protocol_error_if_the_upstream_does_not_list(make_pipeline):
    upstream = FakeUpstream(list_error=RuntimeError("boom"))

    async def go():
        async with Client(build_server(make_pipeline(), upstream)) as agent:
            try:
                await agent.list_tools()
            except MCPError as exc:  # caught inside: the in-memory transport re-raises it on exit too
                return str(exc)

    assert "did not answer" in run(go())


def test_a_call_fails_cleanly_if_the_upstream_does_not_list(make_pipeline):
    upstream = FakeUpstream(list_error=RuntimeError("boom"))

    async def go():
        async with Client(build_server(make_pipeline(), upstream)) as agent:
            return await agent.call_tool("read_document", {"name": "x"})

    result = run(go())
    assert result.is_error and "did not answer" in text_of(result)


def test_a_call_fails_cleanly_if_the_upstream_call_raises(make_pipeline):
    upstream = FakeUpstream(pages=[[tool_object("read_document")]], call_error=RuntimeError("boom"))

    async def go():
        pipeline = make_pipeline()
        async with Client(build_server(pipeline, upstream)) as agent:
            await agent.list_tools()
            return await agent.call_tool("read_document", {"name": "x"})

    result = run(go())
    assert result.is_error and "RuntimeError" in text_of(result) and "boom" not in text_of(result)


def test_module_constants():
    assert proxy.PROXY_NAME == "mcp-security-proxy"
