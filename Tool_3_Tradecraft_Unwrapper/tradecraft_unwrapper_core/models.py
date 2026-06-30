"""Data models used by Tradecraft Unwrapper."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class TransformCandidate:
    """A safely decoded candidate produced by a detector."""

    transform: str
    decoded: bytes
    confidence: int
    evidence: str
    warnings: List[str] = field(default_factory=list)


@dataclass
class Stage:
    """One observed or decoded stage in the transformation lineage."""

    stage_id: int
    parent_id: Optional[int]
    depth: int
    transform: str
    confidence: int
    evidence: str
    input_sha256: str
    output_sha256: str
    input_size: int
    output_size: int
    text: str
    text_encoding: str
    printable_ratio: float
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""

        return asdict(self)


@dataclass(frozen=True)
class Indicator:
    """An indicator extracted from observed content."""

    kind: str
    value: str
    stage_id: int

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""

        return asdict(self)


@dataclass(frozen=True)
class TradecraftFinding:
    """An evidence-based tradecraft hypothesis."""

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: int
    confidence_basis: str
    stage_ids: List[int]
    evidence: List[str]
    attack_id: Optional[str] = None
    attack_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""

        return asdict(self)


@dataclass
class AnalysisResult:
    """Complete analysis result for one input."""

    source: str
    root_sha256: str
    stages: List[Stage]
    indicators: List[Indicator]
    findings: List[TradecraftFinding] = field(default_factory=list)
    ruleset: Dict[str, str] = field(default_factory=dict)

    # Retained internally so exact stage artifacts can be exported.
    # This field is intentionally omitted from to_dict() because bytes
    # are not directly JSON serializable.
    stage_bytes: Dict[int, bytes] = field(
        default_factory=dict,
        repr=False,
    )

    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "source": self.source,
            "root_sha256": self.root_sha256,
            "ruleset": dict(self.ruleset),
            "stages": [
                stage.to_dict()
                for stage in self.stages
            ],
            "indicators": [
                indicator.to_dict()
                for indicator in self.indicators
            ],
            "tradecraft_findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "warnings": list(self.warnings),
        }
