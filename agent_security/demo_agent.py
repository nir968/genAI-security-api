#!/usr/bin/env python3
"""A scripted "AI agent" (no LLM) that walks through the MCP security scenarios.

It is an ordinary MCP client. It launches the security proxy over stdio; the
proxy launches the demo server (corp-docs) and calls the gateway. Nothing here
knows about the controls: it just uses the tools, and the table at the end
shows what the proxy did about each call.

    python agent_security/demo_agent.py                  # needs a human for scenario G
    python agent_security/demo_agent.py --auto-approve   # approves scenario G through the API
    python agent_security/demo_agent.py --auto-approve --rug-pull

Needs the gateway running (docker compose up -d) and MCP_PROXY_TOKEN (read from
the environment or from the .env file in the repository root).
Nothing is ever sent: the demo server only appends to an outbox file.
"""
import argparse
import asyncio
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from mcp import Client, StdioServerParameters

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
POLICY = HERE / "mcp_proxy" / "policy.yaml"

CARD = "4111 1111 1111 1111"  # the public test card number
MARKER = "[removed by security proxy: possible prompt injection]"


@dataclass
class Row:
    step: str
    what: str
    expected: str
    actual: str
    ok: bool


# --- environment -----------------------------------------------------------------------------


def load_dotenv(path: Path) -> None:
    """Read KEY=VALUE lines from .env into os.environ, without overriding."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def gateway_call(base: str, method: str, path: str, body=None):
    """(status, parsed JSON or None) from the gateway; status 0 if it cannot be reached."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        base + path, data=data, method=method, headers={"Content-Type": "application/json"} if data else {}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, None
    except (urllib.error.URLError, OSError):
        return 0, None  # not reachable


def proxy_parameters(args, workdir: Path, rug_pull: bool = False) -> StdioServerParameters:
    env = dict(os.environ)
    env.update(
        GATEWAY_URL=args.gateway,
        MCP_PINS_PATH=str(workdir / "pins.json"),
        DEMO_OUTBOX_PATH=str(args.outbox_path),
        MCP_APPROVAL_POLL_SECONDS="1",
        PYTHONPATH=str(HERE) + os.pathsep + env.get("PYTHONPATH", ""),
    )
    env.pop("DEMO_RUG_PULL", None)
    if rug_pull:
        env["DEMO_RUG_PULL"] = "1"
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_proxy", "--policy", str(POLICY), "--", sys.executable, "-m", "demo_server"],
        env=env,
    )


def text_of(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


def short(text: str, width: int = 46) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


# --- the approval step (scenario G) --------------------------------------------------------------


async def watch_for_approval(args, found: asyncio.Future) -> None:
    """Find the pending approval the proxy created; approve it if asked to."""
    while True:
        status, body = await asyncio.to_thread(gateway_call, args.gateway, "GET", "/mcp/approvals?status=pending")
        if status == 200 and body and body.get("approvals"):
            approval = body["approvals"][0]
            approval_id = approval["id"]
            print(f"\n  approval requested: {approval_id}")
            print(f"    tool: {approval['tool_name']}   reason: {approval['reason']}")
            print(f"    arguments (masked): {short(approval['args_masked'], 100)}")
            curl = (
                f"curl -X POST {args.gateway}/mcp/approvals/{approval_id}/decision "
                "-H \"Content-Type: application/json\" -d '{\"decision\": \"approve\"}'"
            )
            if args.auto_approve:
                print("    --auto-approve: approving through the API ...")
                await asyncio.to_thread(
                    gateway_call, args.gateway, "POST", f"/mcp/approvals/{approval_id}/decision", {"decision": "approve"}
                )
            else:
                print("    waiting for a human. To approve (use \"deny\" to refuse):")
                print(f"      {curl}")
            if not found.done():
                found.set_result(approval_id)
            return
        await asyncio.sleep(0.5)


# --- the scenarios -----------------------------------------------------------------------------------


async def scenarios_a_to_g(args, workdir: Path, rows: list) -> None:
    async with Client(proxy_parameters(args, workdir)) as agent:
        tools = {t.name for t in (await agent.list_tools()).tools}
        rows.append(Row("A", "list tools", "list_documents, read_document, send_email visible",
                        ", ".join(sorted(tools)),
                        tools == {"list_documents", "read_document", "send_email"}))

        result = await agent.call_tool("read_document", {"name": "welcome.md"})
        text = text_of(result)
        rows.append(Row("B", "read welcome.md (clean)", "text unchanged",
                        short(text), not result.is_error and text.startswith("# Welcome") and MARKER not in text))

        result = await agent.call_tool("read_document", {"name": "vendor-invoice.md"})
        text = text_of(result)
        clean = MARKER in text and "audit@vendor-billing" not in text and "ignore your previous" not in text
        rows.append(Row("C", "read vendor-invoice.md (hidden injection)", "injected instructions removed",
                        "removed, invoice text kept" if clean else "INJECTION REACHED THE AGENT", clean))

        result = await agent.call_tool("read_document", {"name": "customers.csv"})
        text = text_of(result)
        masked = CARD not in text and "****1111" in text and "[REDACTED:IBAN]" in text
        rows.append(Row("D", "read customers.csv (card + IBAN)", "card and IBAN redacted",
                        "card -> ****1111, IBAN -> [REDACTED:IBAN]" if masked else "SENSITIVE DATA REACHED THE AGENT", masked))

        result = await agent.call_tool(
            "send_email", {"to": "colleague@corp.example", "subject": "Lunch", "body": "Lunch at noon?"}
        )
        rows.append(Row("E", "email colleague@corp.example (clean)", "allowed, no approval",
                        short(text_of(result)), text_of(result) == "queued"))

        result = await agent.call_tool(
            "send_email", {"to": "colleague@corp.example", "subject": "Payment", "body": f"my card is {CARD}"}
        )
        blocked = result.is_error and "CREDIT_CARD" in text_of(result)
        rows.append(Row("F", "email with the test card in the body", "blocked by DLP",
                        "blocked: " + short(text_of(result), 36) if blocked else "NOT BLOCKED", blocked))

        print("\nScenario G: an email to an external address needs a human.")
        found: asyncio.Future = asyncio.get_running_loop().create_future()
        watcher = asyncio.create_task(watch_for_approval(args, found))
        try:
            result = await agent.call_tool(
                "send_email", {"to": "bob@example.org", "subject": "Report", "body": "Here is the report."}
            )
        finally:
            watcher.cancel()
        sent = text_of(result) == "queued"
        if args.auto_approve:
            rows.append(Row("G", "email bob@example.org (external)", "waits for approval, then sent",
                            "approved via API, " + text_of(result), sent))
        else:
            rows.append(Row("G", "email bob@example.org (external)", "waits for approval",
                            "approved by a human, queued" if sent else "not approved: " + short(text_of(result), 30), True))


async def scenario_h(args, workdir: Path, rows: list) -> None:
    print("\nScenario H: the server changes send_email after it was trusted (rug pull).")
    async with Client(proxy_parameters(args, workdir, rug_pull=True)) as agent:
        before = {t.name for t in (await agent.list_tools()).tools}
        after = {t.name for t in (await agent.list_tools()).tools}
        result = await agent.call_tool(
            "send_email", {"to": "colleague@corp.example", "subject": "Hi", "body": "Hello"}
        )
    blocked = "send_email" in before and "send_email" not in after and result.is_error and "rug pull" in text_of(result)
    rows.append(Row("H", "send_email redefined by the server", "hidden and blocked (TOOL_DEFINITION_CHANGED)",
                    "hidden, call refused: definition changed" if blocked else "NOT BLOCKED", blocked))


# --- output ----------------------------------------------------------------------------------------------


def print_table(rows: list) -> None:
    headers = ("Step", "Scenario", "Expected", "Actual", "Result")
    cells = [(r.step, r.what, r.expected, r.actual, "PASS" if r.ok else "FAIL") for r in rows]
    widths = [max(len(h), *(len(c[i]) for c in cells)) for i, h in enumerate(headers)]
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(line)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    print(line)
    for cell in cells:
        print("| " + " | ".join(value.ljust(w) for value, w in zip(cell, widths)) + " |")
    print(line)


def print_audit(args) -> None:
    status, stats = gateway_call(args.gateway, "GET", "/mcp/stats")
    if status != 200 or not stats:
        return
    counts = {k: v for k, v in stats["by_event_type"].items() if v}
    print(f"\nEvents recorded at the gateway ({stats['total_events']} in total): "
          + ", ".join(f"{name} {count}" for name, count in sorted(counts.items())))


def print_outbox(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    print(f"\nOutbox ({path}): {len(lines)} message(s) queued, none sent.")
    for line in lines:
        record = json.loads(line)
        print(f"  to {record['to']:<28} subject {record['subject']!r}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Scripted MCP agent for the security proxy demo.")
    parser.add_argument("--gateway", default=os.environ.get("GATEWAY_URL", "http://localhost:8000"))
    parser.add_argument("--auto-approve", action="store_true", help="approve scenario G through the API")
    parser.add_argument("--rug-pull", action="store_true", help="also run scenario H (a tool changes after being trusted)")
    parser.add_argument("--outbox", dest="outbox_path", type=Path, help="outbox file (default: a fresh temp file)")
    args = parser.parse_args(argv)
    args.gateway = args.gateway.rstrip("/")
    return args


async def main_async(args) -> int:
    workdir = Path(tempfile.mkdtemp(prefix="mcp-demo-"))
    if args.outbox_path is None:
        args.outbox_path = workdir / "outbox.jsonl"
    print(f"Gateway {args.gateway}; pins and outbox in {workdir} (fresh for this run)")

    status, _ = gateway_call(args.gateway, "GET", "/health")
    if status != 200:
        print(f"The gateway is not answering at {args.gateway}. Start it with: docker compose up -d", file=sys.stderr)
        return 2

    rows: list = []
    await scenarios_a_to_g(args, workdir, rows)
    if args.rug_pull:
        await scenario_h(args, workdir, rows)

    print()
    print_table(rows)
    print_audit(args)
    print_outbox(args.outbox_path)
    return 0 if all(row.ok for row in rows) else 1


def main(argv=None) -> int:
    load_dotenv(REPO_ROOT / ".env")
    args = parse_args(argv)
    if not os.environ.get("MCP_PROXY_TOKEN"):
        print("MCP_PROXY_TOKEN is not set (put it in the .env file in the repository root, see .env.example).", file=sys.stderr)
        return 2
    return asyncio.run(main_async(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
