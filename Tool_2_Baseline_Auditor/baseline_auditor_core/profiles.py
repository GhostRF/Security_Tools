"""Profile loading and validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

from .models import Profile


class ProfileError(ValueError):
    """Raised when a profile cannot be loaded or validated."""


def profiles_directory() -> Path:
    return Path(__file__).resolve().parent.parent / "profiles"


def available_profiles() -> Iterable[Path]:
    return sorted(profiles_directory().glob("*.json"))


def resolve_profile_path(value: str) -> Path:
    candidate = Path(value).expanduser()

    if candidate.exists():
        return candidate.resolve()

    profile_name = value if value.endswith(".json") else f"{value}.json"
    packaged = profiles_directory() / profile_name

    if packaged.exists():
        return packaged.resolve()

    raise ProfileError(
        f"Profile was not found: {value}. "
        f"Use --list-profiles to view bundled profiles."
    )


def _require(mapping: Dict[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise ProfileError(f"{context} is missing required field '{key}'.")
    return mapping[key]


def load_profile(path: Path) -> Profile:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"Could not read profile {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileError(
            f"Profile {path} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ProfileError("Profile root must be a JSON object.")

    profile_id = str(_require(data, "profile_id", "profile"))
    name = str(_require(data, "name", "profile"))
    version = str(_require(data, "version", "profile"))
    description = str(data.get("description", ""))

    weights = _require(data, "severity_weights", "profile")
    if not isinstance(weights, dict):
        raise ProfileError("severity_weights must be a JSON object.")

    severity_weights: Dict[str, int] = {}
    for severity in ("critical", "high", "medium", "low"):
        raw = _require(weights, severity, "severity_weights")
        if not isinstance(raw, int) or raw < 0:
            raise ProfileError(
                f"severity_weights.{severity} must be a non-negative integer."
            )
        severity_weights[severity] = raw

    pass_weight = data.get("pass_weight", 10)
    if not isinstance(pass_weight, int) or pass_weight < 0:
        raise ProfileError("pass_weight must be a non-negative integer.")

    artifacts = _require(data, "artifacts", "profile")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ProfileError("artifacts must be a non-empty JSON object.")

    supported_parsers = {"key_value", "firewall_status", "file_permissions"}
    supported_operators = {
        "equals",
        "in",
        "int_between",
        "int_gte",
        "int_lte",
    }

    for artifact_name, artifact in artifacts.items():
        context = f"artifact '{artifact_name}'"
        if not isinstance(artifact, dict):
            raise ProfileError(f"{context} must be a JSON object.")

        parser_name = str(_require(artifact, "parser", context))
        if parser_name not in supported_parsers:
            raise ProfileError(
                f"{context} uses unsupported parser '{parser_name}'."
            )

        _require(artifact, "category", context)
        missing = _require(artifact, "missing", context)
        if not isinstance(missing, dict):
            raise ProfileError(f"{context}.missing must be a JSON object.")

        for field in (
            "check_id",
            "title",
            "severity",
            "rationale",
            "recommendation",
        ):
            _require(missing, field, f"{context}.missing")

        if parser_name == "key_value":
            rules = _require(artifact, "rules", context)
            if not isinstance(rules, list) or not rules:
                raise ProfileError(
                    f"{context}.rules must be a non-empty JSON array."
                )
            for index, rule in enumerate(rules):
                rule_context = f"{context}.rules[{index}]"
                if not isinstance(rule, dict):
                    raise ProfileError(
                        f"{rule_context} must be a JSON object."
                    )
                for field in (
                    "check_id",
                    "key",
                    "operator",
                    "severity",
                    "title_pass",
                    "title_fail",
                    "rationale",
                    "recommendation",
                ):
                    _require(rule, field, rule_context)
                if rule["operator"] not in supported_operators:
                    raise ProfileError(
                        f"{rule_context} uses unsupported operator "
                        f"'{rule['operator']}'."
                    )

    return Profile(
        profile_id=profile_id,
        name=name,
        version=version,
        description=description,
        severity_weights=severity_weights,
        pass_weight=pass_weight,
        artifacts=artifacts,
    )
