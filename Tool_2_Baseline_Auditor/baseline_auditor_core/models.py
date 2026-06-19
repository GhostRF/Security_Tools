"""Shared data models for the baseline auditor."""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    category: str
    evidence: str
    rationale: str
    recommendation: str


@dataclass(frozen=True)
class Profile:
    profile_id: str
    name: str
    version: str
    description: str
    severity_weights: Dict[str, int]
    pass_weight: int
    artifacts: Dict[str, Dict[str, Any]]
