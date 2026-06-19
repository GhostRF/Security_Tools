"""Summary, scoring, and exit-threshold logic."""

from __future__ import annotations

from typing import Dict, Iterable

from .models import Finding, Profile


SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compliance_score(findings: Iterable[Finding], profile: Profile) -> int:
    applicable = [
        finding
        for finding in findings
        if finding.status in {"PASS", "FAIL"}
    ]
    failed = [
        finding
        for finding in applicable
        if finding.status == "FAIL"
    ]

    if not applicable:
        return 0

    total_penalty = sum(
        profile.severity_weights.get(finding.severity, 0)
        for finding in failed
    )

    max_penalty = sum(
        profile.severity_weights.get(finding.severity, 0)
        if finding.status == "FAIL"
        else profile.pass_weight
        for finding in applicable
    )

    if max_penalty <= 0:
        return 100

    score = 100 - int((total_penalty / max_penalty) * 100)
    return max(0, min(100, score))


def summarize(findings: Iterable[Finding], profile: Profile) -> Dict[str, int]:
    findings_list = list(findings)
    summary = {
        "total_checks": len(findings_list),
        "passed": sum(
            1 for finding in findings_list if finding.status == "PASS"
        ),
        "failed": sum(
            1 for finding in findings_list if finding.status == "FAIL"
        ),
        "critical": sum(
            1
            for finding in findings_list
            if finding.status == "FAIL"
            and finding.severity == "critical"
        ),
        "high": sum(
            1
            for finding in findings_list
            if finding.status == "FAIL"
            and finding.severity == "high"
        ),
        "medium": sum(
            1
            for finding in findings_list
            if finding.status == "FAIL"
            and finding.severity == "medium"
        ),
        "low": sum(
            1
            for finding in findings_list
            if finding.status == "FAIL"
            and finding.severity == "low"
        ),
    }
    summary["compliance_score"] = compliance_score(
        findings_list,
        profile,
    )
    return summary


def threshold_exceeded(
    findings: Iterable[Finding],
    fail_level: str,
) -> bool:
    threshold = SEVERITY_RANK[fail_level]

    return any(
        finding.status == "FAIL"
        and SEVERITY_RANK.get(finding.severity, 0) >= threshold
        for finding in findings
    )
