import pytest

from mcp_proxy.recipients import check_recipients, is_internal_domain, normalize_domain

ALLOWED = ("corp.example",)


def check(to, **extra):
    return check_recipients({"to": to, **extra}, ALLOWED)


# --- one address ------------------------------------------------------------------


def test_an_address_in_the_allowed_domain_is_internal():
    result = check("dana@corp.example")
    assert not result.has_external
    assert result.addresses == ("dana@corp.example",) and result.external == ()


def test_an_address_elsewhere_is_external():
    result = check("bob@example.org")
    assert result.has_external and result.external == ("bob@example.org",)


@pytest.mark.parametrize("address", ["DANA@CORP.EXAMPLE", "dana@Corp.Example", "Dana@corp.example."])
def test_case_and_a_trailing_dot_do_not_matter(address):
    assert not check(address).has_external


def test_the_result_addresses_are_lower_case():
    assert check("Bob@Example.ORG").external == ("bob@example.org",)


# --- subdomains and look-alikes ---------------------------------------------------


@pytest.mark.parametrize("address", ["a@mail.corp.example", "a@eu.mail.corp.example", "a@MAIL.CORP.EXAMPLE"])
def test_subdomains_of_an_allowed_domain_are_internal(address):
    assert not check(address).has_external


@pytest.mark.parametrize(
    "address",
    [
        "a@evilcorp.example",  # shares a suffix but not a label
        "a@corp.example.evil.org",
        "a@corp.examples",
        "a@xcorp.example",
        "a@example",  # parent of the allowed domain
        "a@corp-example.com",
    ],
)
def test_look_alike_domains_are_external(address):
    assert check(address).has_external


def test_is_internal_domain_directly():
    assert is_internal_domain("corp.example", ALLOWED)
    assert is_internal_domain("a.b.corp.example", ALLOWED)
    assert is_internal_domain("CORP.EXAMPLE.", ALLOWED)
    assert not is_internal_domain("badcorp.example", ALLOWED)
    assert not is_internal_domain("corp.example", ())


# --- several recipients -----------------------------------------------------------


def test_one_external_recipient_makes_the_whole_call_external():
    result = check("dana@corp.example, bob@example.org")
    assert result.has_external and result.external == ("bob@example.org",)
    assert result.addresses == ("dana@corp.example", "bob@example.org")


def test_all_internal_recipients_are_internal():
    assert not check("a@corp.example, b@corp.example; c@mail.corp.example").has_external


def test_semicolons_separate_addresses_too():
    assert check("a@corp.example; b@example.org").external == ("b@example.org",)


def test_a_list_of_addresses():
    assert not check(["a@corp.example", "b@corp.example"]).has_external
    assert check(["a@corp.example", "b@example.org"]).external == ("b@example.org",)


@pytest.mark.parametrize("field", ["cc", "bcc", "recipient", "recipients"])
def test_other_recipient_fields_are_checked(field):
    result = check_recipients({"to": "a@corp.example", field: "x@example.org"}, ALLOWED)
    assert result.has_external and result.external == ("x@example.org",)


def test_a_hidden_bcc_is_not_overlooked():
    assert check_recipients({"to": "a@corp.example", "bcc": ["audit@collector.example.org"]}, ALLOWED).has_external


# --- display names ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value, external",
    [
        ('"Dana Levi" <dana@corp.example>', False),
        ("Dana Levi <dana@corp.example>", False),
        ("<dana@corp.example>", False),
        ('"Levi, Dana" <dana@corp.example>', False),
        ('"Bob" <bob@example.org>', True),
        ("Dana <dana@corp.example>, Bob <bob@example.org>", True),
        # the address that counts is the one in <>, not one that appears in the name
        ('"evil@example.org" <dana@corp.example>', False),
        ('"dana@corp.example" <evil@example.org>', True),
    ],
)
def test_display_name_formats(value, external):
    assert check(value).has_external is external


# --- fail closed ------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "   ", "not an address", "dana", "dana@", "@corp.example", "dana@localhost", "a@b@corp.example",
     "dana@corp.example\n", "dana@corp.example\nBcc: evil@example.org", "dana@corp.example\r\n",
     "a@corp.example\x00", "a b@corp.example", "user%evil.org@corp.example", "dana@exa mple.org",
     "dana@сorp.example", 5, None, {"a": 1}, [1, 2], ["a@corp.example", 3]],
)
def test_unclear_recipients_count_as_external(value):
    result = check(value)
    assert result.has_external
    assert result.undetermined or result.external


def test_a_call_with_no_recipient_field_is_unclear():
    result = check_recipients({"subject": "hi", "body": "x"}, ALLOWED)
    assert result.undetermined and result.has_external and result.addresses == ()


def test_arguments_that_are_not_a_mapping_are_unclear():
    assert check_recipients(None, ALLOWED).has_external
    assert check_recipients("a@corp.example", ALLOWED).has_external


def test_one_unparseable_recipient_spoils_an_otherwise_internal_call():
    result = check(["a@corp.example", "garbage"])
    assert result.undetermined and result.has_external


def test_an_empty_list_is_unclear():
    assert check([]).has_external


# --- normalize_domain -------------------------------------------------------------


@pytest.mark.parametrize(
    "address, domain",
    [("a@Corp.Example", "corp.example"), ("a@corp.example.", "corp.example"), (" a@x.org ", "x.org")],
)
def test_normalize_domain(address, domain):
    assert normalize_domain(address) == domain


@pytest.mark.parametrize("address", ["a", "a@", "@x.org", "a@x", "a@-x.org", "a@x..org", "a b@x.org", "a@x_y.org"])
def test_normalize_domain_rejects_bad_addresses(address):
    assert normalize_domain(address) is None
