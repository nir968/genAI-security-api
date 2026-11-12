import hashlib
import json
import os

import pytest

from mcp_proxy import pinning
from mcp_proxy.pinning import (
    PINNED,
    QUARANTINED,
    PinStore,
    PinStoreError,
    args_fingerprint,
    canonical_json,
    sha256_hex,
    tool_fingerprint,
)

SCHEMA = {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}, "required": ["to"]}


# --- canonical hashing ----------------------------------------------------------


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": {"d": [1, 2], "c": None}}) == '{"a":{"c":null,"d":[1,2]},"b":1}'


def test_canonical_json_keeps_non_ascii_text():
    assert canonical_json({"t": "שלום"}) == '{"t":"שלום"}'


def test_key_order_does_not_change_the_hash():
    reordered = {"required": ["to"], "properties": {"body": {"type": "string"}, "to": {"type": "string"}}, "type": "object"}
    assert tool_fingerprint("send_email", "d", SCHEMA) == tool_fingerprint("send_email", "d", reordered)
    assert args_fingerprint({"a": 1, "b": 2}) == args_fingerprint({"b": 2, "a": 1})


def test_the_fingerprint_is_sha256_of_name_description_and_schema():
    expected = hashlib.sha256(
        canonical_json({"name": "t", "description": "d", "inputSchema": SCHEMA}).encode("utf-8")
    ).hexdigest()
    assert tool_fingerprint("t", "d", SCHEMA) == expected
    assert len(expected) == 64


@pytest.mark.parametrize(
    "other",
    [
        ("t", "d2", SCHEMA),  # description changed
        ("t", "d ", SCHEMA),  # one trailing space
        ("t", "D", SCHEMA),  # case
        ("t", "d​", SCHEMA),  # an invisible character
        ("t2", "d", SCHEMA),  # renamed
        ("t", "d", {**SCHEMA, "required": []}),  # schema changed
        ("t", "d", {**SCHEMA, "properties": {**SCHEMA["properties"], "bcc": {"type": "string"}}}),
        ("t", None, SCHEMA),  # description removed
        ("t", "", SCHEMA),
    ],
)
def test_any_change_to_the_definition_changes_the_hash(other):
    assert tool_fingerprint("t", "d", SCHEMA) != tool_fingerprint(*other)


def test_a_missing_description_and_an_empty_one_are_different():
    assert tool_fingerprint("t", None, {}) != tool_fingerprint("t", "", {})


def test_args_fingerprint_depends_on_the_values():
    assert args_fingerprint({"to": "a@corp.example"}) != args_fingerprint({"to": "b@corp.example"})
    assert args_fingerprint({}) == sha256_hex("{}")


# --- the pin store --------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    return PinStore(tmp_path / "state" / "pins.json")


def test_an_unknown_tool_has_no_entry_and_no_file_is_created(store):
    assert store.get("corp-docs", "send_email") is None
    assert store.entries() == []
    assert not store.path.exists()


def test_trust_on_first_use_records_the_hash(store):
    store.record("corp-docs", "send_email", "a" * 64)
    entry = store.get("corp-docs", "send_email")
    assert entry["status"] == PINNED and entry["sha256"] == "a" * 64
    assert entry["recorded_at"].endswith("Z")


def test_pins_persist_across_instances_and_are_per_server(store):
    store.record("corp-docs", "send_email", "a" * 64)
    store.record("other", "send_email", "b" * 64)
    again = PinStore(store.path)
    assert again.get("corp-docs", "send_email")["sha256"] == "a" * 64
    assert again.get("other", "send_email")["sha256"] == "b" * 64
    assert again.get("third", "send_email") is None


def test_recording_again_overwrites_the_entry(store):
    store.record("s", "t", "a" * 64)
    store.record("s", "t", "b" * 64, QUARANTINED)
    assert store.get("s", "t")["sha256"] == "b" * 64 and store.get("s", "t")["status"] == QUARANTINED


def test_an_unknown_status_is_rejected(store):
    with pytest.raises(ValueError):
        store.record("s", "t", "a" * 64, "trusted")


def test_reset_forgets_one_tool(store):
    store.record("s", "one", "a" * 64)
    store.record("s", "two", "b" * 64)
    assert store.reset("s", "one") is True
    assert store.get("s", "one") is None and store.get("s", "two") is not None
    assert store.reset("s", "one") is False
    assert store.reset("nope", "one") is False


def test_resetting_the_last_tool_removes_the_server(store):
    store.record("s", "one", "a" * 64)
    store.reset("s", "one")
    assert json.loads(store.path.read_text())["servers"] == {}


def test_entries_are_sorted(store):
    store.record("b", "z", "1" * 64)
    store.record("a", "y", "2" * 64)
    store.record("a", "x", "3" * 64)
    assert [(s, t) for s, t, _ in store.entries()] == [("a", "x"), ("a", "y"), ("b", "z")]


def test_changes_by_another_process_are_seen_at_once(store):
    store.record("s", "t", "a" * 64)
    PinStore(store.path).reset("s", "t")  # e.g. `python -m mcp_proxy pins reset t`
    assert store.get("s", "t") is None


def test_saving_leaves_no_temp_files(store):
    store.record("s", "t", "a" * 64)
    assert [p.name for p in store.path.parent.iterdir()] == ["pins.json"]


@pytest.mark.parametrize(
    "content",
    ["not json", "[]", '{"servers": []}', '{"servers": {"s": []}}', '{"servers": {"s": {"t": 5}}}', "{}"],
)
def test_a_damaged_pin_file_is_an_error_not_an_empty_store(store, content):
    store.path.parent.mkdir(parents=True)
    store.path.write_text(content, encoding="utf-8")
    with pytest.raises(PinStoreError):
        store.get("s", "t")


def test_an_unreadable_pin_path_is_an_error(tmp_path):
    with pytest.raises(PinStoreError, match="cannot read"):
        PinStore(tmp_path).get("s", "t")  # a directory


def test_a_failed_save_keeps_the_old_file_and_cleans_up(store, monkeypatch):
    store.record("s", "t", "a" * 64)

    def boom(*args):
        raise OSError("disk full")

    monkeypatch.setattr(pinning.os, "replace", boom)
    with pytest.raises(OSError):
        store.record("s", "u", "b" * 64)
    monkeypatch.undo()
    assert store.get("s", "u") is None and store.get("s", "t") is not None
    assert [p.name for p in store.path.parent.iterdir()] == ["pins.json"]


def test_cleanup_errors_do_not_hide_the_original_error(store, monkeypatch):
    def boom(*args):
        raise OSError("disk full")

    monkeypatch.setattr(pinning.os, "replace", boom)
    monkeypatch.setattr(pinning.os, "unlink", boom)
    with pytest.raises(OSError, match="disk full"):
        store.record("s", "t", "a" * 64)
    monkeypatch.undo()
    for leftover in store.path.parent.glob(".pins-*"):
        os.unlink(leftover)
