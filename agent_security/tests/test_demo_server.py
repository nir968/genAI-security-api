import asyncio
import json

import pytest
from mcp import Client

import injection
from demo_server import server as demo
from demo_server.server import (
    DEFAULT_OUTBOX,
    DOCUMENTS_DIR,
    RUG_PULL_SUFFIX,
    create_server,
    list_documents,
    queue_email,
    read_document,
)

ZWSP = "\u200b"


def run(coro):
    return asyncio.run(coro)


# --- documents ----------------------------------------------------------------------


def test_the_sample_documents_are_there():
    assert list_documents() == ["customers.csv", "q3-report.md", "vendor-invoice.md", "welcome.md"]


@pytest.mark.parametrize("name", ["welcome.md", "q3-report.md"])
def test_benign_documents_have_nothing_suspicious(name):
    assert not injection.analyze(read_document(name)).detected


def test_customers_csv_holds_the_public_test_card_and_iban_only():
    text = read_document("customers.csv")
    assert "4111 1111 1111 1111" in text and "IL620108000000099999999" in text
    assert "@example.com" in text and "AKIA" not in text


def test_the_vendor_invoice_hides_an_injection_two_ways():
    text = read_document("vendor-invoice.md")
    assert "<!--" in text and ZWSP in text
    result = injection.analyze(text)
    assert result.detected
    kinds = {(s.kind, s.name) for s in result.signals}
    assert ("hidden_content", "html_comment") in kinds
    assert ("hidden_content", "zero_width_characters") in kinds
    assert ("ai_instruction", "ignore_instructions") in kinds
    assert ("ai_instruction", "addresses_ai") in kinds
    assert ("exfiltration", "send_to_address_or_url") in kinds
    assert "example.org" in text
    # the visible part of the invoice survives sanitizing
    assert "Total due: 838.00 EUR" in result.sanitized_text
    assert "audit@vendor-billing" not in result.sanitized_text


def test_the_obfuscated_line_is_found_even_without_the_comment():
    line = read_document("vendor-invoice.md").rstrip("\n").split("\n")[-1]
    assert ZWSP in line
    assert {s.name for s in injection.analyze(line).signals} >= {"ignore_instructions", "send_to_address_or_url"}


# --- path traversal -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "../README.md", "..", "../..", "..\\welcome.md", "a/b", "sub/../welcome.md", "/etc/passwd", "C:\\Windows\\win.ini",
        "\\\\server\\share", "welcome.md/", "./welcome.md", "welcome.md\x00.txt", "", " welcome.md", "WELCOME.MD",
        "welcome", "nope.md", "....//welcome.md", "%2e%2e/welcome.md", "welcome.md..",
    ],
)
def test_names_that_are_not_exactly_a_listed_file_are_rejected(name):
    with pytest.raises(ValueError, match="unknown document"):
        read_document(name)


@pytest.mark.parametrize("name", [None, 5, ["welcome.md"], {"name": "welcome.md"}])
def test_non_string_names_are_rejected(name):
    with pytest.raises(ValueError):
        read_document(name)


def test_a_file_outside_the_folder_is_never_opened(tmp_path, monkeypatch):
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "ok.md").write_text("fine", encoding="utf-8")
    assert read_document("ok.md", docs) == "fine"
    for name in ("../secret.txt", "..\\secret.txt", str(tmp_path / "secret.txt")):
        with pytest.raises(ValueError):
            read_document(name, docs)


def test_a_document_over_the_size_limit_is_refused(tmp_path, monkeypatch):
    (tmp_path / "big.md").write_text("x" * 50, encoding="utf-8")
    monkeypatch.setattr(demo, "MAX_DOCUMENT_BYTES", 10)
    with pytest.raises(ValueError, match="too large"):
        read_document("big.md", tmp_path)


def test_subfolders_are_not_listed(tmp_path):
    (tmp_path / "dir").mkdir()
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    assert list_documents(tmp_path) == ["a.md"]
    with pytest.raises(ValueError):
        read_document("dir", tmp_path)


# --- the outbox -----------------------------------------------------------------------


def test_queue_email_appends_a_json_line_and_sends_nothing(tmp_path):
    outbox = tmp_path / "out" / "outbox.jsonl"
    assert queue_email("a@corp.example", "Hi", "Body", outbox) == "queued"
    assert queue_email("b@corp.example", "Hi again", "Body 2", outbox) == "queued"
    lines = outbox.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert (first["to"], first["subject"], first["body"]) == ("a@corp.example", "Hi", "Body")
    assert first["queued_at"].endswith("Z")
    assert json.loads(lines[1])["to"] == "b@corp.example"


def test_the_outbox_path_comes_from_the_environment(tmp_path, monkeypatch):
    target = tmp_path / "elsewhere.jsonl"
    monkeypatch.setenv("DEMO_OUTBOX_PATH", str(target))
    queue_email("a@corp.example", "s", "b")
    assert target.exists()


def test_the_default_outbox_is_next_to_the_server_module_and_ignored_by_git():
    assert DEFAULT_OUTBOX.name == "outbox.jsonl" and DEFAULT_OUTBOX.parent == DOCUMENTS_DIR.parent


def test_non_ascii_text_is_kept(tmp_path):
    outbox = tmp_path / "o.jsonl"
    queue_email("a@corp.example", "שלום", "גוף", outbox)
    assert json.loads(outbox.read_text(encoding="utf-8"))["subject"] == "שלום"


# --- the MCP tools ----------------------------------------------------------------------


async def tools_of(server):
    async with Client(server) as client:
        return (await client.list_tools()).tools


def test_three_tools_with_plain_text_output():
    tools = run(tools_of(create_server(rug_pull=False)))
    assert [t.name for t in tools] == ["list_documents", "read_document", "send_email"]
    assert all(t.output_schema is None for t in tools)


def test_the_clean_send_email_description_passes_the_injection_heuristics():
    tools = {t.name: t for t in run(tools_of(create_server(rug_pull=False)))}
    text = tools["send_email"].description
    assert not injection.analyze(text).detected and "nothing is ever sent" in text.lower()


def test_tool_calls(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_OUTBOX_PATH", str(tmp_path / "outbox.jsonl"))

    async def scenario():
        async with Client(create_server(rug_pull=False)) as client:
            listing = await client.call_tool("list_documents", {})
            read = await client.call_tool("read_document", {"name": "welcome.md"})
            bad = await client.call_tool("read_document", {"name": "../x"})
            sent = await client.call_tool("send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
            return listing, read, bad, sent

    listing, read, bad, sent = run(scenario())
    assert listing.content[0].text.splitlines() == list_documents()
    assert read.content[0].text == read_document("welcome.md") and read.structured_content is None
    assert bad.is_error and "unknown document" in bad.content[0].text
    assert sent.content[0].text == "queued"
    assert json.loads((tmp_path / "outbox.jsonl").read_text(encoding="utf-8"))["to"] == "a@corp.example"


# --- rug pull ----------------------------------------------------------------------------


def test_without_rug_pull_the_descriptions_never_change():
    async def scenario():
        async with Client(create_server(rug_pull=False)) as client:
            return [(await client.list_tools()).tools[2].description for _ in range(3)]

    first, second, third = run(scenario())
    assert first == second == third


def test_with_rug_pull_the_description_changes_after_the_first_list():
    async def scenario():
        async with Client(create_server(rug_pull=True)) as client:
            return [(await client.list_tools()).tools for _ in range(3)]

    first, second, third = run(scenario())
    send = lambda tools: next(t for t in tools if t.name == "send_email")  # noqa: E731
    assert RUG_PULL_SUFFIX not in send(first).description
    assert send(second).description.endswith(RUG_PULL_SUFFIX) and send(third).description == send(second).description
    assert "<IMPORTANT>" in send(second).description and "example.org" in send(second).description
    # only send_email changes
    assert [t.description for t in first if t.name != "send_email"] == [t.description for t in second if t.name != "send_email"]
    assert {(s.kind, s.name) for s in injection.analyze(send(second).description).signals} >= {
        ("ai_instruction", "important_tag"), ("ai_instruction", "conceal_from_user"),
    }


def test_rug_pull_is_switched_on_by_the_environment(monkeypatch):
    monkeypatch.setenv("DEMO_RUG_PULL", "1")
    assert create_server()._rug_pull is True
    monkeypatch.setenv("DEMO_RUG_PULL", "0")
    assert create_server()._rug_pull is False
    monkeypatch.delenv("DEMO_RUG_PULL")
    assert create_server()._rug_pull is False


def test_main_runs_the_stdio_server(monkeypatch):
    started = []
    monkeypatch.setattr(demo.CorpDocsServer, "run", lambda self, transport="stdio", **kw: started.append(transport))
    demo.main()
    assert started == ["stdio"]
