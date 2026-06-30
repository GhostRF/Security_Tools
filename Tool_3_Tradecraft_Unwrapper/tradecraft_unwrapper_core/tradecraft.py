"""External rule loading and evidence-based tradecraft evaluation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .models import Indicator, Stage, TradecraftFinding


_ALLOWED_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}

_ATTACK_ID_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$"
)


class RulesetError(ValueError):
    """Raised when an external tradecraft rule set is invalid."""


def default_rules_path() -> Path:
    """Return the bundled default rule-set path."""

    return (
        Path(__file__).resolve().parents[1]
        / "rules"
        / "default.json"
    )


def _require_nonempty_string(
    value: Any,
    field_name: str,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RulesetError(
            f"{field_name} must be a nonempty string."
        )

    return value.strip()


def _validate_rule(
    rule: Any,
    seen_rule_ids: Set[str],
) -> None:
    if not isinstance(rule, dict):
        raise RulesetError(
            "Each rule must be a JSON object."
        )

    rule_id = _require_nonempty_string(
        rule.get("rule_id"),
        "rule_id",
    )

    if rule_id in seen_rule_ids:
        raise RulesetError(
            f"Duplicate rule_id: {rule_id}"
        )

    seen_rule_ids.add(rule_id)

    _require_nonempty_string(
        rule.get("title"),
        f"{rule_id}.title",
    )

    _require_nonempty_string(
        rule.get("description"),
        f"{rule_id}.description",
    )

    severity = _require_nonempty_string(
        rule.get("severity"),
        f"{rule_id}.severity",
    ).lower()

    if severity not in _ALLOWED_SEVERITIES:
        raise RulesetError(
            f"{rule_id}.severity is unsupported: "
            f"{severity}"
        )

    confidence = rule.get("confidence")

    if (
        not isinstance(confidence, int)
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 100
    ):
        raise RulesetError(
            f"{rule_id}.confidence must be "
            "an integer from 0 through 100."
        )

    _require_nonempty_string(
        rule.get("confidence_basis"),
        f"{rule_id}.confidence_basis",
    )

    attack_id = rule.get("attack_id")

    if attack_id is not None:
        attack_id = _require_nonempty_string(
            attack_id,
            f"{rule_id}.attack_id",
        )

        if not _ATTACK_ID_PATTERN.fullmatch(
            attack_id
        ):
            raise RulesetError(
                f"{rule_id}.attack_id has an "
                f"invalid format: {attack_id}"
            )

        _require_nonempty_string(
            rule.get("attack_name"),
            f"{rule_id}.attack_name",
        )

    match = rule.get("match")

    if not isinstance(match, dict):
        raise RulesetError(
            f"{rule_id}.match must be an object."
        )

    match_type = match.get("type")

    if match_type not in {
        "transform",
        "indicator",
    }:
        raise RulesetError(
            f"{rule_id}.match.type must be "
            "'transform' or 'indicator'."
        )

    values = match.get("values")

    if (
        not isinstance(values, list)
        or not values
        or not all(
            isinstance(value, str)
            and value.strip()
            for value in values
        )
    ):
        raise RulesetError(
            f"{rule_id}.match.values must be "
            "a nonempty list of strings."
        )

    if match_type == "indicator":
        _require_nonempty_string(
            match.get("kind"),
            f"{rule_id}.match.kind",
        )


def load_ruleset(
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Load and validate an external JSON rule set."""

    rules_path = (
        default_rules_path()
        if path is None
        else Path(path).expanduser()
    )

    if not rules_path.exists():
        raise RulesetError(
            f"Rule file does not exist: {rules_path}"
        )

    if not rules_path.is_file():
        raise RulesetError(
            f"Rule path is not a file: {rules_path}"
        )

    try:
        data = json.loads(
            rules_path.read_text(
                encoding="utf-8"
            )
        )
    except OSError as error:
        raise RulesetError(
            f"Could not read rule file: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise RulesetError(
            "Rule file is not valid JSON: "
            f"line {error.lineno}, "
            f"column {error.colno}: "
            f"{error.msg}"
        ) from error

    if not isinstance(data, dict):
        raise RulesetError(
            "The rule-set root must be an object."
        )

    if data.get("schema_version") != 1:
        raise RulesetError(
            "Unsupported or missing schema_version. "
            "Expected schema_version 1."
        )

    _require_nonempty_string(
        data.get("ruleset_id"),
        "ruleset_id",
    )

    _require_nonempty_string(
        data.get("name"),
        "name",
    )

    _require_nonempty_string(
        data.get("version"),
        "version",
    )

    rules = data.get("rules")

    if not isinstance(rules, list):
        raise RulesetError(
            "rules must be a JSON list."
        )

    seen_rule_ids: Set[str] = set()

    for rule in rules:
        _validate_rule(
            rule,
            seen_rule_ids,
        )

    data["_source_path"] = str(
        rules_path.resolve()
    )

    return data


def _evaluate_transform_rule(
    rule: Dict[str, Any],
    stages: Iterable[Stage],
) -> TradecraftFinding | None:
    values = {
        value.lower()
        for value in rule["match"]["values"]
    }

    matching_stages = [
        stage
        for stage in stages
        if stage.transform.lower() in values
    ]

    if not matching_stages:
        return None

    evidence = [
        (
            f"Stage {stage.stage_id} used "
            f"transform '{stage.transform}'."
        )
        for stage in matching_stages
    ]

    return _build_finding(
        rule,
        {
            stage.stage_id
            for stage in matching_stages
        },
        evidence,
    )


def _evaluate_indicator_rule(
    rule: Dict[str, Any],
    indicators: Iterable[Indicator],
) -> TradecraftFinding | None:
    kind = rule["match"]["kind"].lower()

    values = {
        value.lower()
        for value in rule["match"]["values"]
    }

    matching_indicators = [
        indicator
        for indicator in indicators
        if (
            indicator.kind.lower() == kind
            and indicator.value.lower()
            in values
        )
    ]

    if not matching_indicators:
        return None

    evidence = [
        (
            f"Stage {indicator.stage_id} contained "
            f"{indicator.kind} indicator "
            f"'{indicator.value}'."
        )
        for indicator in matching_indicators
    ]

    return _build_finding(
        rule,
        {
            indicator.stage_id
            for indicator in matching_indicators
        },
        evidence,
    )


def _build_finding(
    rule: Dict[str, Any],
    stage_ids: Set[int],
    evidence: List[str],
) -> TradecraftFinding:
    return TradecraftFinding(
        rule_id=rule["rule_id"],
        title=rule["title"],
        description=rule["description"],
        severity=rule["severity"].lower(),
        confidence=rule["confidence"],
        confidence_basis=rule["confidence_basis"],
        stage_ids=sorted(stage_ids),
        evidence=evidence,
        attack_id=rule.get("attack_id"),
        attack_name=rule.get("attack_name"),
    )


def evaluate_tradecraft(
    stages: Iterable[Stage],
    indicators: Iterable[Indicator],
    ruleset: Dict[str, Any],
) -> List[TradecraftFinding]:
    """Evaluate validated rules against observed evidence."""

    stage_list = list(stages)
    indicator_list = list(indicators)
    findings: List[TradecraftFinding] = []

    for rule in ruleset["rules"]:
        match_type = rule["match"]["type"]

        if match_type == "transform":
            finding = _evaluate_transform_rule(
                rule,
                stage_list,
            )
        else:
            finding = _evaluate_indicator_rule(
                rule,
                indicator_list,
            )

        if finding is not None:
            findings.append(finding)

    return findings
