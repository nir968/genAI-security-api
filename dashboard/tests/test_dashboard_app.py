import pytest
import requests

import app as dashboard_app

STATS = {
    "total_requests": 4321,
    "blocked_injections": 777,
    "data_leaks_prevented": 555,
    "status": "Active & Secure",
}


class FakeResponse:
    def __init__(self, payload=None, status_code=200, json_error=None):
        self._payload = payload
        self.status_code = status_code
        self._json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload


class GatewayMock:
    """Stands in for requests.get inside the dashboard; records every call."""

    def __init__(self):
        self.calls = []
        self.result = FakeResponse(STATS)

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def gateway(monkeypatch):
    mock = GatewayMock()
    monkeypatch.setattr(dashboard_app.requests, "get", mock.get)
    return mock


def test_dashboard_shows_totals_when_gateway_is_healthy(client, gateway):
    response = client.get("/")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    for value in ("4321", "777", "555"):
        assert value in html
    assert "API Offline" not in html


@pytest.mark.parametrize(
    "failure",
    [
        requests.ConnectionError("gateway down"),
        FakeResponse(status_code=500),
        FakeResponse(json_error=ValueError("not json")),
    ],
    ids=["connection-error", "http-500", "non-json"],
)
def test_dashboard_shows_offline_state_on_gateway_failure(client, gateway, failure):
    gateway.result = failure

    response = client.get("/")

    assert response.status_code == 200
    assert "API Offline" in response.get_data(as_text=True)


def test_stats_call_uses_a_timeout(client, gateway):
    client.get("/")

    url, kwargs = gateway.calls[0]
    assert url.endswith("/stats")
    assert kwargs.get("timeout")


def test_activity_passes_gateway_json_through(client, gateway):
    payload = {"records": [{"timestamp": "2026-01-01T00:00:00Z", "blocked": False}]}
    gateway.result = FakeResponse(payload)

    response = client.get("/api/activity")

    assert response.status_code == 200
    assert response.get_json() == payload
    url, kwargs = gateway.calls[0]
    assert url.endswith("/history")
    assert kwargs["params"] == {"hours": 24}


def test_activity_forwards_hours_param(client, gateway):
    gateway.result = FakeResponse({"records": []})

    client.get("/api/activity?hours=72")

    assert gateway.calls[0][1]["params"] == {"hours": 72}


def test_activity_returns_502_when_gateway_unreachable(client, gateway):
    gateway.result = requests.ConnectionError("gateway down")

    response = client.get("/api/activity")

    assert response.status_code == 502
    assert "error" in response.get_json()
