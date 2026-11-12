"""Test doubles for the gateway.

Two doubles share one ``GatewayState``:

* ``FakeGateway``  - the in-process object the pipeline talks to (same async
  methods as ``mcp_proxy.gateway_client.GatewayClient``), with failure injection;
* ``stub_gateway`` - a real HTTP server on 127.0.0.1 for the end-to-end tests,
  where the proxy runs as a subprocess and speaks HTTP.

/scan uses the gateway's real DLP engine and injection heuristics, so the tests
see the behaviour the proxy gets in production, without a database.
"""
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import injection
from dlp import engine as dlp_engine
from mcp_proxy.gateway_client import GatewayError

TOKEN = "test-token-for-the-stub"  # not a secret: only the stub accepts it


def scan_response(text: str, kind: str) -> dict:
    """What the gateway's POST /scan answers (same logic as gateway/mcp_security.py)."""
    direction = "output" if kind == "tool_result" else "input"
    dlp = dlp_engine.scan(text, direction=direction)
    inj = injection.analyze(text)
    return {
        "dlp": {
            "action": dlp.action,
            "risk_score": dlp.risk_score,
            "data_types": dlp.data_types,
            "redacted_text": dlp.redacted_text,
        },
        "injection": inj.to_dict(),
        "safe_text": dlp_engine.scan(inj.sanitized_text, direction=direction).redacted_text,
    }


class GatewayState:
    """Everything the proxy sent, and how approvals are decided."""

    def __init__(self):
        self.events = []
        self.approvals = {}
        self.scans = []  # (kind, text)
        # "pending" leaves approvals open; "approve" / "deny" decide them at once
        self.auto_decision = "pending"
        self.approval_overrides = {}  # fields to overwrite in every approval record

    def scan(self, text, kind):
        self.scans.append((kind, text))
        return scan_response(text, kind)

    def create_approval(self, fields):
        approval_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        record = dict(fields)
        record.update(
            id=approval_id,
            status="pending",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=fields.get("timeout_seconds", 120))).isoformat(),
        )
        record.pop("timeout_seconds", None)
        self.approvals[approval_id] = record
        return {"id": approval_id, "expires_at": record["expires_at"]}

    def get_approval(self, approval_id):
        record = self.approvals.get(approval_id)
        if record is None:
            return None
        if record["status"] == "pending" and self.auto_decision in ("approve", "deny"):
            record["status"] = "approved" if self.auto_decision == "approve" else "denied"
        return {**record, **self.approval_overrides}

    def event_types(self):
        return [event["event_type"] for event in self.events]


class FakeGateway:
    """Drop-in for GatewayClient, for pipeline tests."""

    def __init__(self, state=None):
        self.state = state or GatewayState()
        self.down = False  # every call raises GatewayError
        self.fail = set()  # method names that raise GatewayError
        self.event_status = None  # make post_event raise a GatewayError with this status
        self.polls = 0
        self.decide_after = None  # (n, "approved"|"denied"|"expired"): decide on the n-th poll

    def _check(self, name):
        if self.down or name in self.fail:
            raise GatewayError("cannot reach the gateway (test)")

    async def scan(self, text, kind):
        self._check("scan")
        return self.state.scan(text, kind)

    async def post_event(self, event):
        self._check("post_event")
        if self.event_status is not None:
            raise GatewayError(f"the gateway answered HTTP {self.event_status}", self.event_status)
        self.state.events.append(event)

    async def create_approval(self, **fields):
        self._check("create_approval")
        return self.state.create_approval(fields)

    async def get_approval(self, approval_id):
        self._check("get_approval")
        self.polls += 1
        if self.decide_after and self.polls >= self.decide_after[0]:
            self.state.approvals[approval_id]["status"] = self.decide_after[1]
        return self.state.get_approval(approval_id)

    async def is_available(self):
        return not self.down


@pytest.fixture
def state():
    return GatewayState()


@pytest.fixture
def gateway(state):
    return FakeGateway(state)


class _Handler(BaseHTTPRequestHandler):
    server_state: GatewayState

    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self):
        if self.headers.get("X-Proxy-Token") != TOKEN:
            self._send(401, {"detail": {"error": "Invalid or missing X-Proxy-Token"}})
            return False
        return True

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if not self._authorized():
            return None
        if self.path.startswith("/mcp/approvals/"):
            record = self.server_state.get_approval(self.path.rsplit("/", 1)[1])
            return self._send(200, record) if record else self._send(404, {"detail": {"error": "not found"}})
        return self._send(404, {})

    def do_POST(self):
        if not self._authorized():
            return None
        body = self._body()
        state = self.server_state
        if self.path == "/scan":
            return self._send(200, state.scan(body["text"], body["kind"]))
        if self.path == "/mcp/events":
            state.events.append(body)
            return self._send(201, {"id": len(state.events)})
        if self.path == "/mcp/approvals":
            return self._send(201, state.create_approval(body))
        return self._send(404, {})


class StubGateway:
    def __init__(self, state):
        self.state = state
        handler = type("Handler", (_Handler,), {"server_state": state})
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self.token = TOKEN
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def stub_gateway(state):
    server = StubGateway(state)
    server.start()
    yield server
    server.stop()
