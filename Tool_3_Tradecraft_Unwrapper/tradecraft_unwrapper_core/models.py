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


@dataclass
class AnalysisResult:
    """Complete analysis result for one input."""

    source: str
    root_sha256: str
    stages: List[Stage]
    indicators: List[Indicator]
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "source": self.source,
            "root_sha256": self.root_sha256,
            "stages": [stage.to_dict() for stage in self.stages],
            "indicators": [
                indicator.to_dict()
                for indicator in self.indicators
            ],
            "warnings": list(self.warnings),
        }
