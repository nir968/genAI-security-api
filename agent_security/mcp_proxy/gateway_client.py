"""Async client for the gateway endpoints the proxy uses.

Every failure (gateway down, timeout, HTTP error, unexpected body) becomes a
``GatewayError`` with a short message that never contains the response body or
the request text, so it is safe to log. Callers decide what to do (the pipeline
fails closed).
"""
from typing import Optional

import httpx


class GatewayError(Exception):
    """A request to the gateway failed. ``status`` is the HTTP status, or None if
    the gateway could not be reached at all."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class GatewayClient:
    def __init__(self, base_url: str, token: str, timeout: float = 10.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers={"X-Proxy-Token": token},
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, payload=None) -> dict:
        try:
            response = await self._client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise GatewayError(f"cannot reach the gateway ({type(exc).__name__})") from None
        if response.status_code >= 400:
            raise GatewayError(f"the gateway answered HTTP {response.status_code}", response.status_code)
        try:
            body = response.json()
        except ValueError:
            raise GatewayError("the gateway sent a response that is not JSON", response.status_code) from None
        if not isinstance(body, dict):
            raise GatewayError("the gateway sent an unexpected response", response.status_code)
        return body

    async def scan(self, text: str, kind: str) -> dict:
        """POST /scan -> {"dlp": ..., "injection": ..., "safe_text": ...}."""
        body = await self._request("POST", "/scan", {"text": text, "kind": kind})
        if not isinstance(body.get("dlp"), dict) or not isinstance(body.get("injection"), dict):
            raise GatewayError("the gateway's scan response has an unexpected shape")
        return body

    async def post_event(self, event: dict) -> None:
        """POST /mcp/events."""
        await self._request("POST", "/mcp/events", event)

    async def create_approval(self, **fields) -> dict:
        """POST /mcp/approvals -> {"id", "expires_at"}."""
        body = await self._request("POST", "/mcp/approvals", fields)
        if not isinstance(body.get("id"), str):
            raise GatewayError("the gateway's approval response has an unexpected shape")
        return body

    async def get_approval(self, approval_id: str) -> dict:
        """GET /mcp/approvals/{id}."""
        return await self._request("GET", f"/mcp/approvals/{approval_id}")

    async def is_available(self) -> bool:
        """GET /health. Never raises."""
        try:
            response = await self._client.get("/health")
        except httpx.HTTPError:
            return False
        return response.status_code == 200
