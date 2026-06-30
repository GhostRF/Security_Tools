"""Tests for external tradecraft rules and ATT&CK hypotheses."""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.pipeline import (
    AnalyzerConfig,
    analyze_bytes,
)
from tradecraft_unwrapper_core.reporters import (
    render_summary,
)
from tradecraft_unwrapper_core.tradecraft import (
    RulesetError,
    load_ruleset,
)


class TradecraftRuleTests(unittest.TestCase):
    """Validate conservative evidence-based tradecraft findings."""

    def setUp(self) -> None:
        self.configuration = AnalyzerConfig(
            max_depth=5,
            max_output_bytes=1_048_576,
            min_printable_ratio=0.60,
        )

    def test_benign_plaintext_has_no_findings(self) -> None:
        result = analyze_bytes(
            b'Write-Output "Benign sample"',
            "test-input",
            self.configuration,
        )

        self.assertEqual(
            result.findings,
            [],
        )

    def test_base64_maps_to_t1027(self) -> None:
        encoded = base64.b64encode(
            b'Write-Output "Encoded sample"'
        )

        result = analyze_bytes(
            encoded,
            "test-input",
            self.configuration,
        )

        attack_ids = {
            finding.attack_id
            for finding in result.findings
        }

        self.assertIn(
            "T1027",
            attack_ids,
        )

    def test_powershell_maps_to_t1059_001(self) -> None:
        result = analyze_bytes(
            b'powershell.exe -NoProfile -Command "Write-Output test"',
            "test-input",
            self.configuration,
        )

        attack_ids = {
            finding.attack_id
            for finding in result.findings
        }

        self.assertIn(
            "T1059.001",
            attack_ids,
        )

    def test_cmd_maps_to_t1059_003(self) -> None:
        result = analyze_bytes(
            b"cmd.exe /c echo training",
            "test-input",
            self.configuration,
        )

        attack_ids = {
            finding.attack_id
            for finding in result.findings
        }

        self.assertIn(
            "T1059.003",
            attack_ids,
        )

    def test_proxy_execution_utilities_are_mapped(self) -> None:
        samples = {
            b"mshta.exe training.hta": "T1218.005",
            b"regsvr32.exe training.dll": "T1218.010",
            b"rundll32.exe training.dll,Entry": "T1218.011",
        }

        for content, expected_id in samples.items():
            with self.subTest(
                expected_id=expected_id
            ):
                result = analyze_bytes(
                    content,
                    "test-input",
                    self.configuration,
                )

                attack_ids = {
                    finding.attack_id
                    for finding in result.findings
                }

                self.assertIn(
                    expected_id,
                    attack_ids,
                )

    def test_ruleset_metadata_is_recorded(self) -> None:
        result = analyze_bytes(
            b"cmd.exe /c echo metadata",
            "test-input",
            self.configuration,
        )

        self.assertEqual(
            result.ruleset["ruleset_id"],
            "default-conservative",
        )

        self.assertEqual(
            result.ruleset["version"],
            "1.0",
        )

    def test_custom_rule_file_is_supported(self) -> None:
        custom_rules = {
            "schema_version": 1,
            "ruleset_id": "test-custom",
            "name": "Test Custom Rules",
            "version": "1.0",
            "description": "Test-only rule set.",
            "rules": [
                {
                    "rule_id": "TEST-001",
                    "title": "Curl observed",
                    "description": "Test-only curl rule.",
                    "severity": "low",
                    "confidence": 75,
                    "confidence_basis": (
                        "An exact curl command indicator was "
                        "observed for this test rule."
                    ),
                    "match": {
                        "type": "indicator",
                        "kind": "command",
                        "values": [
                            "curl"
                        ]
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temporary:
            rules_path = (
                Path(temporary)
                / "custom.json"
            )

            rules_path.write_text(
                json.dumps(custom_rules),
                encoding="utf-8",
            )

            result = analyze_bytes(
                b"curl https://example.invalid/training",
                "test-input",
                AnalyzerConfig(
                    rules_path=rules_path
                ),
            )

        self.assertEqual(
            len(result.findings),
            1,
        )

        self.assertEqual(
            result.findings[0].rule_id,
            "TEST-001",
        )

    def test_invalid_rule_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rules_path = (
                Path(temporary)
                / "invalid.json"
            )

            rules_path.write_text(
                '{"schema_version": 99}',
                encoding="utf-8",
            )

            with self.assertRaises(RulesetError):
                load_ruleset(rules_path)


    def test_finding_records_and_reports_confidence_basis(
        self,
    ) -> None:
        result = analyze_bytes(
            b"powershell.exe -NoProfile",
            "test-input",
            self.configuration,
        )

        finding = next(
            item
            for item in result.findings
            if item.rule_id == "TC-002"
        )

        self.assertTrue(
            finding.confidence_basis
        )

        summary = render_summary(result)

        self.assertIn(
            "Confidence basis:",
            summary,
        )

        self.assertIn(
            finding.confidence_basis,
            summary,
        )

        serialized = result.to_dict()

        serialized_finding = next(
            item
            for item in serialized[
                "tradecraft_findings"
            ]
            if item["rule_id"] == "TC-002"
        )

        self.assertEqual(
            serialized_finding[
                "confidence_basis"
            ],
            finding.confidence_basis,
        )

    def test_missing_confidence_basis_is_rejected(
        self,
    ) -> None:
        invalid_rules = {
            "schema_version": 1,
            "ruleset_id": "missing-basis",
            "name": "Missing Basis Test",
            "version": "1.0",
            "description": "Test-only invalid rules.",
            "rules": [
                {
                    "rule_id": "TEST-002",
                    "title": "Invalid rule",
                    "description": (
                        "This rule intentionally omits "
                        "confidence_basis."
                    ),
                    "severity": "low",
                    "confidence": 50,
                    "match": {
                        "type": "indicator",
                        "kind": "command",
                        "values": [
                            "curl"
                        ]
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temporary:
            rules_path = (
                Path(temporary)
                / "missing-basis.json"
            )

            rules_path.write_text(
                json.dumps(invalid_rules),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                RulesetError,
                "confidence_basis",
            ):
                load_ruleset(rules_path)


if __name__ == "__main__":
    unittest.main()
