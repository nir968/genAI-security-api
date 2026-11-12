import copy

import pytest
import yaml

from dlp import engine
from dlp.models import DATA_TYPES
from dlp.policy import DEFAULT_POLICY_PATH, PolicyError, load_policy, parse_policy


def default_document():
    with open(DEFAULT_POLICY_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_default_policy_loads_and_covers_every_type():
    policy = load_policy()
    assert set(policy.rules) == set(DATA_TYPES)


@pytest.mark.parametrize(
    "data_type, action, risk, min_confidence",
    [
        ("CREDIT_CARD", "block", 80, "low"),
        ("IBAN", "redact", 60, "medium"),
        ("IL_ID", "redact", 60, "medium"),
        ("EMAIL", "alert", 30, "medium"),
        ("PHONE_IL", "alert", 30, "medium"),
        ("AWS_ACCESS_KEY", "block", 90, "low"),
        ("GITHUB_TOKEN", "block", 90, "low"),
        ("PRIVATE_KEY", "block", 90, "low"),
        ("JWT", "block", 90, "low"),
        ("CREDENTIAL_ASSIGNMENT", "block", 90, "low"),
        ("HIGH_ENTROPY_SECRET", "alert", 40, "low"),
    ],
)
def test_default_policy_values(data_type, action, risk, min_confidence):
    rule = load_policy().rules[data_type]
    assert (rule.action, rule.risk_score, rule.min_confidence) == (action, risk, min_confidence)


def test_output_direction_turns_block_into_redact():
    policy = load_policy()
    assert policy.action_for("CREDIT_CARD", "input") == "block"
    assert policy.action_for("CREDIT_CARD", "output") == "redact"
    assert policy.action_for("IBAN", "output") == "redact"
    assert policy.action_for("EMAIL", "output") == "alert"


def test_parse_accepts_the_default_document():
    assert parse_policy(default_document()).rules["JWT"].action == "block"


def mutate(change):
    document = copy.deepcopy(default_document())
    change(document["data_types"])
    return document


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda t: t.update({"NOT_A_TYPE": dict(t["JWT"])}), "unknown data type"),
        (lambda t: t["JWT"].update(action="explode"), "unknown action"),
        (lambda t: t["JWT"].pop("risk_score"), "missing field"),
        (lambda t: t["JWT"].pop("action"), "missing field"),
        (lambda t: t["JWT"].pop("min_confidence"), "missing field"),
        (lambda t: t["JWT"].update(extra=1), "unknown field"),
        (lambda t: t["JWT"].update(risk_score=101), "risk_score"),
        (lambda t: t["JWT"].update(risk_score="high"), "risk_score"),
        (lambda t: t["JWT"].update(risk_score=True), "risk_score"),
        (lambda t: t["JWT"].update(min_confidence="certain"), "min_confidence"),
        (lambda t: t.pop("EMAIL"), "does not cover"),
        (lambda t: t.update(JWT="block"), "rule must be a mapping"),
    ],
)
def test_invalid_policy_documents_raise_clear_errors(change, message):
    with pytest.raises(PolicyError, match=message):
        parse_policy(mutate(change))


@pytest.mark.parametrize("document", [None, [], {"other": 1}, {"data_types": []}])
def test_invalid_top_level_shape_raises(document):
    with pytest.raises(PolicyError):
        parse_policy(document)


def test_load_policy_wraps_file_and_yaml_errors(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.yaml")
    broken = tmp_path / "broken.yaml"
    broken.write_text("data_types: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(broken)


def test_load_policy_error_names_the_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"data_types": {"NOPE": {}}}), encoding="utf-8")
    with pytest.raises(PolicyError, match="bad.yaml"):
        load_policy(bad)


def test_init_policy_reads_the_path_from_the_environment(tmp_path, monkeypatch):
    document = default_document()
    document["data_types"]["EMAIL"]["action"] = "block"
    custom = tmp_path / "custom.yaml"
    custom.write_text(yaml.safe_dump(document), encoding="utf-8")
    monkeypatch.setenv("DLP_POLICY_PATH", str(custom))

    policy = engine.init_policy()

    assert policy.rules["EMAIL"].action == "block"
    assert engine.scan("dana@example.com").action == "block"
