"""Tool pinning: trust on first use (TOFU) for tool definitions.

An MCP server describes each tool with a name, a description and an input
schema, and the model reads that text. A malicious or compromised server can
change it after the user has looked at it (a "rug pull") or ship it poisoned
from the start. The proxy therefore fingerprints every tool definition:

* the first time a tool is seen, its description is scanned; if it is clean the
  fingerprint is *pinned*, otherwise the tool is *quarantined*;
* on later lists, a pinned tool whose fingerprint changed is blocked.

A human re-approves a tool with ``python -m mcp_proxy pins reset <tool>``.

Limit: TOFU trusts whatever version it sees first.
"""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PINNED = "pinned"
QUARANTINED = "quarantined"
_VERSION = 1


def canonical_json(value) -> str:
    """Deterministic JSON: sorted keys, no whitespace, non-ASCII kept as is.

    Key order and formatting never change the text, so they never change a hash.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_fingerprint(name: str, description, input_schema) -> str:
    """SHA-256 over the canonical JSON of {name, description, inputSchema}."""
    return sha256_hex(
        canonical_json({"name": name, "description": description, "inputSchema": input_schema})
    )


def args_fingerprint(arguments) -> str:
    """SHA-256 of the exact arguments of a call (canonical JSON)."""
    return sha256_hex(canonical_json(arguments))


class PinStoreError(Exception):
    """The pin file exists but cannot be read or has an unexpected shape."""


class PinStore:
    """A small JSON file: ``{"version": 1, "servers": {server: {tool: entry}}}``.

    The file is read on every call (it is tiny), so ``pins reset`` from another
    terminal takes effect in a running proxy at once. Writes are atomic.
    """

    def __init__(self, path):
        self.path = Path(path)

    def _load(self) -> dict:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"version": _VERSION, "servers": {}}
        except OSError as exc:
            raise PinStoreError(f"cannot read pin file {self.path}: {exc.strerror or exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise PinStoreError(f"pin file {self.path} is not valid JSON") from exc
        servers = data.get("servers") if isinstance(data, dict) else None
        if not isinstance(servers, dict) or not all(
            isinstance(tools, dict) and all(isinstance(entry, dict) for entry in tools.values())
            for tools in servers.values()
        ):
            raise PinStoreError(f"pin file {self.path} has an unexpected structure")
        return data

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=self.path.parent, prefix=".pins-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as temp:
                json.dump(data, temp, indent=2, sort_keys=True)
                temp.write("\n")
            os.replace(temp_name, self.path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def get(self, server: str, tool: str):
        """The entry ``{"status", "sha256", "recorded_at"}`` or None if never seen."""
        return self._load()["servers"].get(server, {}).get(tool)

    def record(self, server: str, tool: str, sha256: str, status: str = PINNED) -> None:
        if status not in (PINNED, QUARANTINED):
            raise ValueError(f"unknown pin status {status!r}")
        data = self._load()
        data["servers"].setdefault(server, {})[tool] = {
            "status": status,
            "sha256": sha256,
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self._save(data)

    def reset(self, server: str, tool: str) -> bool:
        """Forget a tool, so the next list treats it as new. True if it was known."""
        data = self._load()
        tools = data["servers"].get(server, {})
        if tool not in tools:
            return False
        del tools[tool]
        if not tools:
            del data["servers"][server]
        self._save(data)
        return True

    def entries(self) -> list:
        """``[(server, tool, entry), ...]`` sorted by server and tool."""
        data = self._load()
        return [
            (server, tool, entry)
            for server, tools in sorted(data["servers"].items())
            for tool, entry in sorted(tools.items())
        ]
