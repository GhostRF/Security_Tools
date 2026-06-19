"""Profile-driven baseline checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, Profile
from .parsers import (
    get_value,
    is_world_writable_mode,
    parse_int,
    parse_key_value_config,
    parse_permissions_csv,
    read_text_file,
)


def pass_finding(
    check_id: str,
    title: str,
    category: str,
    evidence: str,
    rationale: str,
    recommendation: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        status="PASS",
        severity="informational",
        category=category,
        evidence=evidence,
        rationale=rationale,
        recommendation=recommendation,
    )


def fail_finding(
    check_id: str,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    rationale: str,
    recommendation: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        status="FAIL",
        severity=severity,
        category=category,
        evidence=evidence,
        rationale=rationale,
        recommendation=recommendation,
    )


def _missing_finding(
    artifact_name: str,
    artifact: Dict[str, Any],
) -> Finding:
    missing = artifact["missing"]
    return fail_finding(
        str(missing["check_id"]),
        str(missing["title"]),
        str(missing["severity"]),
        str(artifact["category"]),
        f"{artifact_name} was not found in the target directory.",
        str(missing["rationale"]),
        str(missing["recommendation"]),
    )


def _evaluate_operator(
    raw_value: Optional[str],
    rule: Dict[str, Any],
) -> Tuple[bool, bool]:
    """
    Return (passed, malformed).

    malformed is True when a value is present but cannot be interpreted for the
    configured operator.
    """
    operator = str(rule["operator"])

    if raw_value is None:
        return False, False

    if operator == "equals":
        expected = str(rule["expected"])
        return raw_value.strip().lower() == expected.strip().lower(), False

    if operator == "in":
        expected_values = {
            str(item).strip().lower()
            for item in rule.get("expected", [])
        }
        return raw_value.strip().lower() in expected_values, False

    numeric = parse_int(raw_value)
    if numeric is None:
        return False, True

    if operator == "int_between":
        minimum = int(rule["minimum"])
        maximum = int(rule["maximum"])
        return minimum <= numeric <= maximum, False

    if operator == "int_gte":
        return numeric >= int(rule["minimum"]), False

    if operator == "int_lte":
        return numeric <= int(rule["maximum"]), False

    return False, True


def _evidence(key: str, value: Optional[str]) -> str:
    return f"{key} {value if value is not None else 'not set'}"


def _check_key_value_artifact(
    target_dir: Path,
    artifact_name: str,
    artifact: Dict[str, Any],
) -> List[Finding]:
    path = target_dir / artifact_name
    text = read_text_file(path)

    if text is None:
        return [_missing_finding(artifact_name, artifact)]

    category = str(artifact["category"])
    parsed = parse_key_value_config(text)
    findings: List[Finding] = []

    if parsed.malformed_lines:
        findings.append(
            fail_finding(
                f"INPUT-{artifact_name.upper().replace('.', '-')}",
                f"Malformed line(s) found in {artifact_name}",
                "low",
                "Input Validation",
                "; ".join(parsed.malformed_lines[:5]),
                "Malformed lines may be skipped during parsing and can make the "
                "assessment incomplete.",
                "Correct the malformed lines or provide a clean export before "
                "relying on the assessment.",
            )
        )

    for rule in artifact["rules"]:
        raw_value = get_value(parsed.values, str(rule["key"]))
        passed, malformed = _evaluate_operator(raw_value, rule)

        if passed:
            findings.append(
                pass_finding(
                    str(rule["check_id"]),
                    str(rule["title_pass"]),
                    category,
                    _evidence(str(rule["key"]), raw_value),
                    str(rule["rationale"]),
                    str(rule["recommendation"]),
                )
            )
            continue

        title = str(rule["title_fail"])
        rationale = str(rule["rationale"])

        if malformed:
            title = f"Malformed value for {rule['key']}"
            rationale = (
                f"The value for {rule['key']} was present but could not be "
                "interpreted as required by the selected profile. "
                + rationale
            )

        findings.append(
            fail_finding(
                str(rule["check_id"]),
                title,
                str(rule["severity"]),
                category,
                _evidence(str(rule["key"]), raw_value),
                rationale,
                str(rule["recommendation"]),
            )
        )

    return findings


def _check_firewall_status(
    target_dir: Path,
    artifact_name: str,
    artifact: Dict[str, Any],
) -> List[Finding]:
    path = target_dir / artifact_name
    text = read_text_file(path)

    if text is None:
        return [_missing_finding(artifact_name, artifact)]

    rule = artifact["rule"]
    lower = text.lower()
    enabled_patterns = [
        str(pattern).lower()
        for pattern in rule.get("enabled_patterns", [])
    ]
    disabled_patterns = [
        str(pattern).lower()
        for pattern in rule.get("disabled_patterns", [])
    ]

    enabled = (
        any(pattern in lower for pattern in enabled_patterns)
        and not any(pattern in lower for pattern in disabled_patterns)
    )

    if enabled:
        return [
            pass_finding(
                str(rule["check_id"]),
                str(rule["title_pass"]),
                str(artifact["category"]),
                text.strip()[:200],
                str(rule["rationale"]),
                str(rule["recommendation"]),
            )
        ]

    return [
        fail_finding(
            str(rule["check_id"]),
            str(rule["title_fail"]),
            str(rule["severity"]),
            str(artifact["category"]),
            text.strip()[:200] or "file is empty",
            str(rule["rationale"]),
            str(rule["recommendation"]),
        )
    ]


def _check_file_permissions(
    target_dir: Path,
    artifact_name: str,
    artifact: Dict[str, Any],
) -> List[Finding]:
    path = target_dir / artifact_name

    if not path.exists() or not path.is_file():
        return [_missing_finding(artifact_name, artifact)]

    parsed = parse_permissions_csv(path)
    rule = artifact["rule"]
    findings: List[Finding] = []

    if parsed.errors:
        findings.append(
            fail_finding(
                str(artifact.get("format_check_id", "FILE-002")),
                "File permission inventory contains malformed data",
                str(artifact.get("format_severity", "low")),
                "Input Validation",
                "; ".join(parsed.errors[:5]),
                "Malformed CSV rows or missing columns can cause permission "
                "records to be skipped.",
                "Provide a CSV with complete path, owner, group, and mode "
                "columns before relying on the results.",
            )
        )

        # Do not report a clean permission check when no usable records could
        # be parsed from a malformed inventory.
        if not parsed.rows:
            return findings

    risky_rows = []
    for row in parsed.rows:
        if is_world_writable_mode(row["mode"]):
            risky_rows.append((row["path"], row["mode"]))

    if not risky_rows:
        findings.append(
            pass_finding(
                str(rule["check_id"]),
                str(rule["title_pass"]),
                str(artifact["category"]),
                f"Reviewed {len(parsed.rows)} file permission records.",
                str(rule["rationale"]),
                str(rule["recommendation"]),
            )
        )
    else:
        evidence = "; ".join(
            f"{path_value} ({mode})"
            for path_value, mode in risky_rows[:10]
        )
        findings.append(
            fail_finding(
                str(rule["check_id"]),
                str(rule["title_fail"]),
                str(rule["severity"]),
                str(artifact["category"]),
                evidence,
                str(rule["rationale"]),
                str(rule["recommendation"]),
            )
        )

    return findings


def run_audit(target_dir: Path, profile: Profile) -> List[Finding]:
    findings: List[Finding] = []

    for artifact_name, artifact in profile.artifacts.items():
        parser_name = artifact["parser"]

        if parser_name == "key_value":
            findings.extend(
                _check_key_value_artifact(
                    target_dir,
                    artifact_name,
                    artifact,
                )
            )
        elif parser_name == "firewall_status":
            findings.extend(
                _check_firewall_status(
                    target_dir,
                    artifact_name,
                    artifact,
                )
            )
        elif parser_name == "file_permissions":
            findings.extend(
                _check_file_permissions(
                    target_dir,
                    artifact_name,
                    artifact,
                )
            )

    return findings
