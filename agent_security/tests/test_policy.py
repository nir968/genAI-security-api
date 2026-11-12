import pytest
import yaml

from mcp_proxy.policy import DEFAULT_PATH, PolicyError, ToolPolicy, load_policy, parse_policy


def doc(**overrides):
    base = {
        "server": "corp-docs",
        "allowed_email_domains": ["corp.example"],
        "approval_timeout_seconds": 120,
        "tools": {"read_document": {"allowed": True}},
    }
    base.update(overrides)
    return base


# --- the shipped default -------------------------------------------------------


def test_default_policy_matches_the_spec():
    policy = load_policy()
    assert DEFAULT_PATH.name == "policy.yaml"
    assert policy.server == "corp-docs"
    assert policy.allowed_email_domains == ("corp.example",)
    assert policy.approval_timeout_seconds == 120
    assert policy.tool("list_documents") == ToolPolicy(True, False, True, "never")
    assert policy.tool("read_document") == ToolPolicy(True, False, True, "never")
    assert policy.tool("send_email") == ToolPolicy(True, True, False, "external_recipient")


def test_tools_that_are_not_listed_are_denied():
    policy = load_policy()
    assert policy.tool("delete_everything") is None
    assert policy.is_allowed("send_email")
    assert not policy.is_allowed("delete_everything")


def test_a_listed_tool_can_be_switched_off():
    policy = parse_policy(doc(tools={"send_email": {"allowed": False}}))
    assert not policy.is_allowed("send_email")


# --- defaults ------------------------------------------------------------------


def test_scanning_defaults_to_on_and_approval_to_never():
    rule = parse_policy(doc(tools={"t": {}})).tool("t")
    assert rule == ToolPolicy(allowed=True, scan_args=True, scan_results=True, requires_approval="never")


def test_a_tool_with_no_rules_at_all_gets_the_defaults():
    assert parse_policy(doc(tools={"t": None})).tool("t") == ToolPolicy()


def test_an_empty_tools_section_is_valid_and_denies_everything():
    policy = parse_policy(doc(tools={}))
    assert policy.tools == {} and not policy.is_allowed("anything")


def test_the_timeout_defaults_to_120():
    document = doc()
    del document["approval_timeout_seconds"]
    assert parse_policy(document).approval_timeout_seconds == 120


def test_domains_are_normalised():
    policy = parse_policy(doc(allowed_email_domains=["Corp.Example", " mail.example. "]))
    assert policy.allowed_email_domains == ("corp.example", "mail.example")


def test_domains_are_optional_without_an_external_recipient_rule():
    document = doc()
    del document["allowed_email_domains"]
    assert parse_policy(document).allowed_email_domains == ()


# --- validation: anything unknown or wrong refuses to load ----------------------


@pytest.mark.parametrize(
    "document, message",
    [
        (None, "must be a mapping"),
        ("text", "must be a mapping"),
        ([], "must be a mapping"),
        (doc(extra=1), "unknown key"),
        (doc(server=None), "'server'"),
        (doc(server=""), "'server'"),
        (doc(server="bad name"), "'server'"),
        (doc(tools=None), "'tools'"),
        (doc(tools=["read_document"]), "'tools'"),
        (doc(tools={"t": {"allow": True}}), "unknown key"),
        (doc(tools={"t": {"scan_result": False}}), "unknown key"),
        (doc(tools={"t": {"allowed": "yes"}}), "true or false"),
        (doc(tools={"t": {"scan_args": 1}}), "true or false"),
        (doc(tools={"t": {"scan_results": None}}), "true or false"),
        (doc(tools={"t": {"requires_approval": "sometimes"}}), "requires_approval"),
        (doc(tools={"t": {"requires_approval": True}}), "requires_approval"),
        (doc(tools={"t": "allowed"}), "must be a mapping"),
        (doc(tools={"": {}}), "non-empty"),
        (doc(tools={5: {}}), "non-empty"),
        (doc(allowed_email_domains="corp.example"), "list"),
        (doc(allowed_email_domains=["not a domain"]), "invalid domain"),
        (doc(allowed_email_domains=["a@b.example"]), "invalid domain"),
        (doc(allowed_email_domains=[5]), "invalid domain"),
        (doc(approval_timeout_seconds=0), "approval_timeout_seconds"),
        (doc(approval_timeout_seconds=3601), "approval_timeout_seconds"),
        (doc(approval_timeout_seconds="120"), "approval_timeout_seconds"),
        (doc(approval_timeout_seconds=True), "approval_timeout_seconds"),
        (doc(approval_timeout_seconds=1.5), "approval_timeout_seconds"),
    ],
)
def test_invalid_policies_are_refused(document, message):
    with pytest.raises(PolicyError, match=message):
        parse_policy(document)


def test_external_recipient_needs_allowed_domains():
    document = doc(tools={"send_email": {"requires_approval": "external_recipient"}}, allowed_email_domains=[])
    with pytest.raises(PolicyError, match="allowed_email_domains"):
        parse_policy(document)


def test_always_does_not_need_domains():
    document = doc(tools={"t": {"requires_approval": "always"}}, allowed_email_domains=[])
    assert parse_policy(document).tool("t").requires_approval == "always"


# --- loading from a file --------------------------------------------------------


def test_load_policy_from_a_file(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump(doc()), encoding="utf-8")
    assert load_policy(path).server == "corp-docs"
    assert load_policy(str(path)).server == "corp-docs"


def test_a_missing_file_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml_is_a_policy_error(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("server: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(path)


def test_an_empty_file_is_a_policy_error(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_policy(path)


def test_a_typo_in_a_file_stops_the_load(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("server: s\ntools:\n  t:\n    scan_result: false\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="scan_result"):
        load_policy(path)
