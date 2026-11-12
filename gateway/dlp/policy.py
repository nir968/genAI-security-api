"""Loading and validating the DLP policy file."""
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml

from .models import ACTIONS, CONFIDENCES, DATA_TYPES

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")

# On the output direction (model answers) a "block" rule redacts instead.
OUTPUT_BLOCK_ACTION = "redact"

_RULE_FIELDS = {"action", "risk_score", "min_confidence"}


class PolicyError(ValueError):
    """The policy file is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Rule:
    action: str
    risk_score: int
    min_confidence: str


@dataclass(frozen=True)
class Policy:
    rules: Mapping[str, Rule]

    def action_for(self, data_type: str, direction: str = "input") -> str:
        action = self.rules[data_type].action
        if direction == "output" and action == "block":
            return OUTPUT_BLOCK_ACTION
        return action


def parse_policy(data) -> Policy:
    """Validate an already-parsed policy document and build a Policy."""
    if not isinstance(data, dict) or set(data) != {"data_types"}:
        raise PolicyError("policy must be a mapping with a single 'data_types' key")
    types = data["data_types"]
    if not isinstance(types, dict):
        raise PolicyError("'data_types' must be a mapping of data type -> rule")

    unknown = sorted(set(map(str, types)) - set(DATA_TYPES))
    if unknown:
        raise PolicyError(f"unknown data type(s) in policy: {', '.join(unknown)}")
    missing = [name for name in DATA_TYPES if name not in types]
    if missing:
        raise PolicyError(
            f"policy does not cover data type(s): {', '.join(missing)} "
            "(use action: allow to disable one)"
        )

    rules = {}
    for name, raw in types.items():
        if not isinstance(raw, dict):
            raise PolicyError(f"{name}: rule must be a mapping")
        absent = sorted(_RULE_FIELDS - set(raw))
        if absent:
            raise PolicyError(f"{name}: missing field(s): {', '.join(absent)}")
        extra = sorted(set(map(str, raw)) - _RULE_FIELDS)
        if extra:
            raise PolicyError(f"{name}: unknown field(s): {', '.join(extra)}")
        if raw["action"] not in ACTIONS:
            raise PolicyError(
                f"{name}: unknown action {raw['action']!r} (expected one of {', '.join(ACTIONS)})"
            )
        score = raw["risk_score"]
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise PolicyError(f"{name}: risk_score must be an integer from 0 to 100")
        if raw["min_confidence"] not in CONFIDENCES:
            raise PolicyError(
                f"{name}: unknown min_confidence {raw['min_confidence']!r} "
                f"(expected one of {', '.join(CONFIDENCES)})"
            )
        rules[name] = Rule(raw["action"], score, raw["min_confidence"])
    return Policy(rules)


def load_policy(path=None) -> Policy:
    """Read and validate a policy file (the bundled one by default)."""
    path = Path(path) if path else DEFAULT_POLICY_PATH
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        raise PolicyError(f"cannot read DLP policy {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in DLP policy {path}: {exc}") from exc
    try:
        return parse_policy(data)
    except PolicyError as exc:
        raise PolicyError(f"invalid DLP policy {path}: {exc}") from exc
