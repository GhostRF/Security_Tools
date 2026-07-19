"""Tests for provenance, lineage, and XZ naming."""

from __future__ import annotations

import lzma
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.models import (
    TransformCandidate,
)
from tradecraft_unwrapper_core.pipeline import (
    AnalyzerConfig,
    analyze_bytes,
)
from tradecraft_unwrapper_core.reporters import (
    render_html,
    render_summary,
)


class ProvenanceAndLineageTests(unittest.TestCase):
    """Verify report provenance and deduplicated lineage."""

    def test_provenance_records_execution_context(
        self,
    ) -> None:
        configuration = AnalyzerConfig()

        result = analyze_bytes(
            b"ordinary benign training text",
            "provenance-input",
            configuration,
        )

        provenance = result.provenance

        self.assertEqual(
            provenance["tool_name"],
            "Tradecraft Unwrapper",
        )
        self.assertEqual(
            provenance["tool_version"],
            "1.1.0",
        )
        self.assertEqual(
            provenance["analysis_mode"],
            "static-non-executing",
        )
        self.assertEqual(
            provenance["lineage_policy"],
            "unique-output-sha256-deduplication",
        )
        self.assertTrue(
            provenance["python_version"]
        )
        self.assertRegex(
            provenance["generated_at_utc"],
            r"^\d{4}-\d{2}-\d{2}T.*Z$",
        )
        self.assertEqual(
            provenance["limits"]["max_input_bytes"],
            configuration.max_input_bytes,
        )
        self.assertEqual(
            provenance["limits"]["max_stages"],
            configuration.max_stages,
        )

    def test_provenance_is_serialized_and_rendered(
        self,
    ) -> None:
        result = analyze_bytes(
            b"ordinary benign training text",
            "rendered-provenance-input",
            AnalyzerConfig(),
        )

        serialized = result.to_dict()
        summary = render_summary(result)
        html = render_html(result)

        self.assertIn(
            "provenance",
            serialized,
        )
        self.assertEqual(
            serialized["provenance"]["tool_version"],
            "1.1.0",
        )
        self.assertIn(
            "Tool version: 1.1.0",
            summary,
        )
        self.assertIn(
            "Generated UTC:",
            summary,
        )
        self.assertIn(
            "Configured limits:",
            summary,
        )
        self.assertIn(
            "<strong>Tool version:</strong>",
            html,
        )
        self.assertIn(
            "Configured analysis limits",
            html,
        )

    def test_duplicate_stage_warning_identifies_original(
        self,
    ) -> None:
        first = TransformCandidate(
            transform="first-transform",
            decoded=b"derived training stage",
            confidence=90,
            evidence="First test transformation.",
        )

        duplicate = TransformCandidate(
            transform="duplicate-transform",
            decoded=b"derived training stage",
            confidence=90,
            evidence="Duplicate test transformation.",
        )

        with patch(
            "tradecraft_unwrapper_core."
            "pipeline.detect_transforms",
            side_effect=[
                [first, duplicate],
                [],
            ],
        ):
            result = analyze_bytes(
                b"root training stage",
                "duplicate-lineage-input",
                AnalyzerConfig(),
            )

        self.assertEqual(
            len(result.stages),
            2,
        )

        self.assertTrue(
            any(
                "duplicate-transform"
                in warning
                and "already represented by stage 1"
                in warning
                for warning in result.warnings
            )
        )

    def test_xz_stage_uses_accurate_name(
        self,
    ) -> None:
        payload = (
            b'Write-Output "XZ naming test"'
        )

        compressed = lzma.compress(
            payload,
            format=lzma.FORMAT_XZ,
        )

        result = analyze_bytes(
            compressed,
            "xz-name-input",
            AnalyzerConfig(),
        )

        self.assertTrue(
            any(
                stage.transform == "xz"
                and "XZ naming test"
                in stage.text
                for stage in result.stages
            )
        )

        self.assertFalse(
            any(
                stage.transform == "lzma-xz"
                for stage in result.stages
            )
        )

    def test_reports_describe_unique_lineage(
        self,
    ) -> None:
        result = analyze_bytes(
            b"ordinary benign training text",
            "lineage-wording-input",
            AnalyzerConfig(),
        )

        summary = render_summary(result)
        html = render_html(result)

        self.assertIn(
            "Unique stages recorded:",
            summary,
        )
        self.assertIn(
            "duplicate SHA-256 outputs suppressed",
            summary,
        )
        self.assertIn(
            "Recorded stage lineage",
            html,
        )
        self.assertIn(
            "Unique stages",
            html,
        )


if __name__ == "__main__":
    unittest.main()
