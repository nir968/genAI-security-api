import asyncio
import json

import httpx
import pytest

from mcp_proxy.gateway_client import GatewayClient, GatewayError

SCAN_OK = {
    "dlp": {"action": "allow", "risk_score": 10, "data_types": [], "redacted_text": "x"},
    "injection": {"detected": False, "signals": [], "sanitized_text": "x"},
    "safe_text": "x",
}


def run(coro):
    return asyncio.run(coro)


def client_for(handler, **kwargs):
    return GatewayClient("http://gateway.test", "test-token", transport=httpx.MockTransport(handler), **kwargs)


def test_scan_posts_text_and_kind_with_the_token():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=SCAN_OK)

    result = run(client_for(handler).scan("hello", "tool_result"))
    assert result["safe_text"] == "x"
    request = seen[0]
    assert (request.method, str(request.url)) == ("POST", "http://gateway.test/scan")
    assert request.headers["x-proxy-token"] == "test-token"
    assert json.loads(request.content) == {"text": "hello", "kind": "tool_result"}


def test_a_trailing_slash_in_the_base_url_is_ignored():
    client = GatewayClient("http://gateway.test/", "t", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=SCAN_OK)))
    assert client.base_url == "http://gateway.test"


def test_post_event_sends_the_event():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(201, json={"id": 1})

    run(client_for(handler).post_event({"event_type": "TOOL_CALL_ALLOWED"}))
    assert seen == [("POST", "/mcp/events", {"event_type": "TOOL_CALL_ALLOWED"})]


def test_create_and_get_approval():
    def handler(request):
        if request.method == "POST":
            assert json.loads(request.content)["tool_name"] == "send_email"
            return httpx.Response(201, json={"id": "abc", "expires_at": "2026-01-01T00:00:00Z"})
        assert request.url.path == "/mcp/approvals/abc"
        return httpx.Response(200, json={"id": "abc", "status": "pending"})

    client = client_for(handler)
    assert run(client.create_approval(tool_name="send_email", server_name="s"))["id"] == "abc"
    assert run(client.get_approval("abc"))["status"] == "pending"


@pytest.mark.parametrize("status", [401, 403, 404, 422, 500, 503])
def test_http_errors_become_gateway_errors_without_the_body(status):
    client = client_for(lambda r: httpx.Response(status, text="secret body 4111 1111 1111 1111"))
    with pytest.raises(GatewayError) as excinfo:
        run(client.scan("text with a secret", "tool_args"))
    assert excinfo.value.status == status
    assert str(status) in str(excinfo.value)
    assert "secret" not in str(excinfo.value)


@pytest.mark.parametrize(
    "exception", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("bad")]
)
def test_network_failures_become_gateway_errors(exception):
    def handler(request):
        raise exception

    with pytest.raises(GatewayError, match="cannot reach the gateway") as excinfo:
        run(client_for(handler).scan("x", "tool_args"))
    assert excinfo.value.status is None
    assert type(exception).__name__ in str(excinfo.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=["a", "list"]),
        httpx.Response(200, json={"dlp": {}}),  # scan without an injection section
        httpx.Response(200, json={"dlp": "x", "injection": {}}),
    ],
)
def test_unexpected_scan_responses_are_errors(response):
    with pytest.raises(GatewayError):
        run(client_for(lambda r: response).scan("x", "tool_args"))


def test_an_approval_response_without_an_id_is_an_error():
    with pytest.raises(GatewayError, match="unexpected shape"):
        run(client_for(lambda r: httpx.Response(201, json={"expires_at": "x"})).create_approval(tool_name="t"))


def test_is_available():
    assert run(client_for(lambda r: httpx.Response(200, json={"status": "ok"})).is_available()) is True
    assert run(client_for(lambda r: httpx.Response(503)).is_available()) is False

    def refused(request):
        raise httpx.ConnectError("refused")

    assert run(client_for(refused).is_available()) is False


def test_aclose():
    client = client_for(lambda r: httpx.Response(200, json=SCAN_OK))
    run(client.aclose())
