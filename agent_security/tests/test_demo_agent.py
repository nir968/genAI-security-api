"""The demo agent itself, run for real against the stub gateway (real proxy and
demo server in child processes), plus its helpers."""
import asyncio
import json

import pytest

import demo_agent
from demo_agent import Row

TIMEOUT = 150


@pytest.fixture
def agent_env(monkeypatch, stub_gateway, tmp_path):
    monkeypatch.setenv("MCP_PROXY_TOKEN", stub_gateway.token)
    monkeypatch.delenv("DEMO_RUG_PULL", raising=False)
    workdir = tmp_path / "demo"
    workdir.mkdir()
    monkeypatch.setattr(demo_agent.tempfile, "mkdtemp", lambda prefix="": str(workdir))
    return workdir


def run_demo(stub_gateway, *flags, human=None):
    """Run the demo. ``human`` ("approved" / "denied") decides the first approval
    request after a pause, like a person reading the instructions first."""
    args = demo_agent.parse_args(["--gateway", stub_gateway.url, *flags])

    async def go():
        async def decide():
            while not stub_gateway.state.approvals:
                await asyncio.sleep(0.05)
            await asyncio.sleep(1.5)  # long enough for the demo to print what to do
            next(iter(stub_gateway.state.approvals.values()))["status"] = human

        task = asyncio.create_task(decide()) if human else None
        code = await demo_agent.main_async(args)
        if task:
            await task
        return code

    return asyncio.run(asyncio.wait_for(go(), TIMEOUT))


def test_every_scenario_passes_with_auto_approve_and_rug_pull(agent_env, stub_gateway, state, capsys):
    assert run_demo(stub_gateway, "--auto-approve", "--rug-pull") == 0
    out = capsys.readouterr().out

    rows = [line for line in out.splitlines() if line.startswith("| ") and ("PASS" in line or "FAIL" in line)]
    assert [line.split("|")[1].strip() for line in rows] == list("ABCDEFGH")
    assert all("PASS" in line and "FAIL" not in line for line in rows)

    assert "approval requested:" in out and "--auto-approve: approving through the API" in out
    assert "Outbox" in out and "2 message(s) queued, none sent" in out
    # only the allowed and the approved email reached the outbox
    outbox = [json.loads(line) for line in (agent_env / "outbox.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [m["to"] for m in outbox] == ["colleague@corp.example", "bob@example.org"]

    types = state.event_types()
    for expected in ("RESULT_INJECTION_REMOVED", "RESULT_REDACTED", "ARGS_DLP_BLOCKED", "APPROVAL_REQUESTED",
                     "APPROVAL_GRANTED", "TOOL_DEFINITION_CHANGED"):
        assert expected in types
    assert "4111" not in json.dumps(state.events) and "audit@" not in json.dumps(state.events)
    assert "Events recorded at the gateway" in out


def test_without_auto_approve_it_prints_the_curl_command_and_waits_for_a_human(agent_env, stub_gateway, state, capsys):
    assert run_demo(stub_gateway, human="approved") == 0
    out = capsys.readouterr().out
    assert "waiting for a human" in out
    assert f"curl -X POST {stub_gateway.url}/mcp/approvals/" in out and "/decision" in out
    assert "approved by a human, queued" in out
    assert "H" not in [line.split("|")[1].strip() for line in out.splitlines() if line.startswith("| ")]  # no rug pull


def test_a_human_who_denies_makes_scenario_g_report_not_approved(agent_env, stub_gateway, state, capsys):
    assert run_demo(stub_gateway, human="denied") == 0  # a denial is an expected outcome, not a failure of the demo
    assert "not approved" in capsys.readouterr().out


def test_it_stops_when_the_gateway_is_not_running(agent_env, capsys):
    args = demo_agent.parse_args(["--gateway", "http://127.0.0.1:9"])
    assert asyncio.run(demo_agent.main_async(args)) == 2
    assert "is not answering" in capsys.readouterr().err


def test_main_needs_a_token(monkeypatch, capsys):
    monkeypatch.delenv("MCP_PROXY_TOKEN", raising=False)
    monkeypatch.setattr(demo_agent, "REPO_ROOT", demo_agent.HERE / "no-such-dir")
    assert demo_agent.main([]) == 2
    assert "MCP_PROXY_TOKEN is not set" in capsys.readouterr().err


def test_main_runs_the_demo(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_TOKEN", "t")
    monkeypatch.setattr(demo_agent, "REPO_ROOT", demo_agent.HERE / "no-such-dir")
    seen = []

    async def fake_main_async(args):
        seen.append(args)
        return 0

    monkeypatch.setattr(demo_agent, "main_async", fake_main_async)
    assert demo_agent.main(["--auto-approve", "--gateway", "http://x:1/"]) == 0
    assert seen[0].auto_approve and seen[0].gateway == "http://x:1"


# --- helpers --------------------------------------------------------------------------------


def test_load_dotenv_reads_values_without_overriding(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text('# comment\n\nA_ONE=1\nA_TWO="two words"\nA_THREE=\'3\'\nA_SET=file\nnot a pair\n', encoding="utf-8")
    for name in ("A_ONE", "A_TWO", "A_THREE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("A_SET", "environment")
    demo_agent.load_dotenv(path)
    import os

    assert (os.environ["A_ONE"], os.environ["A_TWO"], os.environ["A_THREE"], os.environ["A_SET"]) == (
        "1", "two words", "3", "environment")
    for name in ("A_ONE", "A_TWO", "A_THREE"):
        monkeypatch.delenv(name)


def test_load_dotenv_ignores_a_missing_file(tmp_path):
    demo_agent.load_dotenv(tmp_path / "nope")


def test_gateway_call_returns_status_and_body(stub_gateway):
    assert demo_agent.gateway_call(stub_gateway.url, "GET", "/health") == (200, {"status": "ok"})
    assert demo_agent.gateway_call(stub_gateway.url, "GET", "/nope")[0] == 401  # the stub wants a token for unknown paths
    assert demo_agent.gateway_call("http://127.0.0.1:9", "GET", "/health") == (0, None)


def test_gateway_call_decision_conflict(stub_gateway, state):
    assert demo_agent.gateway_call(stub_gateway.url, "POST", "/mcp/approvals/x/decision", {"decision": "approve"})[0] == 409


def test_short_collapses_whitespace_and_truncates():
    assert demo_agent.short("a  b\nc") == "a b c"
    assert demo_agent.short("x" * 100, 10) == "x" * 7 + "..."


def test_print_table_aligns_columns(capsys):
    demo_agent.print_table([Row("A", "one", "exp", "act", True), Row("B", "a longer scenario", "e", "a", False)])
    lines = capsys.readouterr().out.splitlines()
    assert len({len(line) for line in lines}) == 1  # every line the same width
    assert "PASS" in lines[3] and "FAIL" in lines[4]


def test_print_audit_and_outbox_are_quiet_when_there_is_nothing(tmp_path, capsys):
    demo_agent.print_audit(demo_agent.parse_args(["--gateway", "http://127.0.0.1:9"]))
    demo_agent.print_outbox(tmp_path / "missing.jsonl")
    out = capsys.readouterr().out
    assert "0 message(s) queued" in out and "Events recorded" not in out


def test_parse_args_defaults(monkeypatch):
    monkeypatch.delenv("GATEWAY_URL", raising=False)
    args = demo_agent.parse_args([])
    assert args.gateway == "http://localhost:8000" and not args.auto_approve and not args.rug_pull
    monkeypatch.setenv("GATEWAY_URL", "http://gw:1/")
    assert demo_agent.parse_args([]).gateway == "http://gw:1"
