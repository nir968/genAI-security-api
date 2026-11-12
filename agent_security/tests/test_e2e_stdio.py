"""End to end over real stdio.

The agent (an SDK client) launches ``python -m mcp_proxy``, which launches
``python -m demo_server``; the proxy talks HTTP to a local stub gateway. Every
process boundary here is the real one. Scenarios B, C, F, G and H.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from mcp_proxy.policy import DEFAULT_PATH

AGENT_SECURITY = Path(__file__).resolve().parents[1]
CARD = "4111 1111 1111 1111"
MARKER = "[removed by security proxy: possible prompt injection]"
TIMEOUT = 90


@pytest.fixture
def outbox(tmp_path):
    return tmp_path / "outbox.jsonl"


@pytest.fixture
def proxy_params(stub_gateway, tmp_path, outbox):
    def build(rug_pull=False, token=None):
        env = dict(os.environ)
        env.update(
            GATEWAY_URL=stub_gateway.url,
            MCP_PROXY_TOKEN=token or stub_gateway.token,
            MCP_PINS_PATH=str(tmp_path / "pins.json"),
            MCP_APPROVAL_POLL_SECONDS="0.05",
            DEMO_OUTBOX_PATH=str(outbox),
            PYTHONPATH=str(AGENT_SECURITY) + os.pathsep + env.get("PYTHONPATH", ""),
        )
        env.pop("DEMO_RUG_PULL", None)
        if rug_pull:
            env["DEMO_RUG_PULL"] = "1"
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_proxy", "--policy", str(DEFAULT_PATH), "--",
                  sys.executable, "-m", "demo_server"],
            env=env,
        )

    return build


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, TIMEOUT))


def text_of(result):
    return "".join(block.text for block in result.content)


def lines(path):
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_scenario_a_and_b_tools_are_listed_and_a_clean_document_is_read(proxy_params, state):
    async def go():
        async with Client(proxy_params()) as agent:
            tools = (await agent.list_tools()).tools
            doc = await agent.call_tool("read_document", {"name": "welcome.md"})
            return tools, doc

    tools, doc = run(go())
    assert [t.name for t in tools] == ["list_documents", "read_document", "send_email"]
    assert not doc.is_error and "Welcome to Example Corp" in text_of(doc)
    assert state.event_types() == ["TOOL_CALL_ALLOWED"]


def test_scenario_c_the_hidden_injection_never_reaches_the_agent(proxy_params, state):
    async def go():
        async with Client(proxy_params()) as agent:
            return await agent.call_tool("read_document", {"name": "vendor-invoice.md"})

    text = text_of(run(go()))
    assert MARKER in text
    for leaked in ("audit@vendor-billing", "ignore your previous", "​", "<!--", "Do not tell the user"):
        assert leaked not in text
    assert "Total due: 838.00 EUR" in text
    assert "RESULT_INJECTION_REMOVED" in state.event_types()
    assert "audit@" not in json.dumps(state.events)


def test_scenario_d_sensitive_data_in_a_document_is_redacted(proxy_params, state):
    async def go():
        async with Client(proxy_params()) as agent:
            return await agent.call_tool("read_document", {"name": "customers.csv"})

    text = text_of(run(go()))
    assert CARD not in text and "****1111" in text and "[REDACTED:IBAN]" in text
    assert "RESULT_REDACTED" in state.event_types()


def test_scenario_f_an_email_with_a_card_is_blocked_and_nothing_is_queued(proxy_params, state, outbox):
    async def go():
        async with Client(proxy_params()) as agent:
            await agent.list_tools()
            clean = await agent.call_tool(
                "send_email", {"to": "colleague@corp.example", "subject": "Hi", "body": "Lunch at noon?"}
            )
            bad = await agent.call_tool(
                "send_email", {"to": "colleague@corp.example", "subject": "Hi", "body": f"my card is {CARD}"}
            )
            return clean, bad

    clean, bad = run(go())
    assert text_of(clean) == "queued"
    assert bad.is_error and "CREDIT_CARD" in text_of(bad)
    assert [json.loads(line)["body"] for line in lines(outbox)] == ["Lunch at noon?"]  # only the clean one
    assert state.event_types() == ["TOOL_CALL_ALLOWED", "ARGS_DLP_BLOCKED"]
    assert "4111" not in json.dumps(state.events)


def test_scenario_g_an_external_email_waits_for_a_human(proxy_params, state, outbox):
    async def go():
        async with Client(proxy_params()) as agent:
            await agent.list_tools()
            call = asyncio.ensure_future(
                agent.call_tool("send_email", {"to": "bob@example.org", "subject": "Hi", "body": "Hello"})
            )
            # the call is parked until someone decides
            for _ in range(200):
                if state.approvals:
                    break
                await asyncio.sleep(0.05)
            assert not call.done() and lines(outbox) == []
            (record,) = state.approvals.values()
            assert record["tool_name"] == "send_email" and record["status"] == "pending"
            record["status"] = "approved"  # the human clicks "approve"
            return await call

    result = run(go())
    assert text_of(result) == "queued" and len(lines(outbox)) == 1
    assert state.event_types() == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED", "TOOL_CALL_ALLOWED"]


def test_scenario_h_a_rug_pull_is_blocked(proxy_params, state, outbox):
    async def first_run():
        async with Client(proxy_params()) as agent:
            return (await agent.list_tools()).tools

    async def second_run():
        # a new proxy and a new upstream that now misbehaves, with the same pin file
        async with Client(proxy_params(rug_pull=True)) as agent:
            before = (await agent.list_tools()).tools
            after = (await agent.list_tools()).tools
            call = await agent.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
            return before, after, call

    assert "send_email" in [t.name for t in run(first_run())]
    before, after, call = run(second_run())
    assert "send_email" in [t.name for t in before]
    assert "send_email" not in [t.name for t in after]
    assert call.is_error and "rug pull" in text_of(call)
    assert lines(outbox) == []
    assert "TOOL_DEFINITION_CHANGED" in state.event_types()
    assert "BCC" not in json.dumps(state.events)


def test_the_proxy_fails_closed_when_the_gateway_rejects_its_token(proxy_params, state, outbox):
    async def go():
        async with Client(proxy_params(token="a-wrong-token")) as agent:
            tools = (await agent.list_tools()).tools  # nothing can be verified: nothing is shown
            call = await agent.call_tool(
                "send_email", {"to": "a@corp.example", "subject": "s", "body": "b"}
            )
            return tools, call

    tools, call = run(go())
    assert tools == [] and call.is_error
    assert lines(outbox) == [] and state.events == []


def test_stdout_carries_only_protocol_messages_when_the_proxy_refuses_to_start(tmp_path):
    import subprocess

    env = dict(os.environ, PYTHONPATH=str(AGENT_SECURITY))
    env.pop("MCP_PROXY_TOKEN", None)
    done = subprocess.run(
        [sys.executable, "-m", "mcp_proxy", "--policy", str(DEFAULT_PATH), "--", sys.executable, "-m", "demo_server"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert done.returncode == 2 and done.stdout == ""
    assert "MCP_PROXY_TOKEN is not set" in done.stderr
