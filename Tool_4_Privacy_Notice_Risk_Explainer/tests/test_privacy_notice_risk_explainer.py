import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "privacy_notice_risk_explainer.py"


def run_tool(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


class PrivacyNoticeRiskExplainerTests(unittest.TestCase):
    def test_version_command(self):
        result = run_tool("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1.1.0", result.stdout)

    def test_high_risk_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/high_risk_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Risk level: CRITICAL", result.stdout)
            self.assertIn("Risk score: 38", result.stdout)
            self.assertIn("Findings: 10", result.stdout)

            out = Path(tmp)
            self.assertTrue((out / "analysis.json").is_file())
            self.assertTrue((out / "summary.txt").is_file())
            self.assertTrue((out / "report.html").is_file())
            self.assertTrue((out / "findings.csv").is_file())

            with (out / "analysis.json").open(encoding="utf-8") as f:
                json.load(f)

    def test_low_risk_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/low_risk_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Risk level: LOW", result.stdout)
            self.assertIn("Risk score: 0", result.stdout)
            self.assertIn("Findings: 0", result.stdout)

    def test_ambiguous_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/ambiguous_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Risk level: MODERATE", result.stdout)
            self.assertIn("Risk score: 8", result.stdout)
            self.assertIn("Findings: 3", result.stdout)

    def test_app_permissions_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/app_permissions_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Risk level: HIGH", result.stdout)
            self.assertIn("Risk score: 14", result.stdout)
            self.assertIn("Findings: 4", result.stdout)

    def test_indirect_vague_language_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/indirect_language_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)

            data = json.loads((Path(tmp) / "analysis.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in data["findings"]}
            self.assertIn("PN-011", rule_ids)
            self.assertIn("PN-012", rule_ids)

    def test_custom_rule_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool(
                "samples/custom_rule_notice.txt",
                "--rules",
                "samples/custom_rules.json",
                "-o",
                tmp,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Custom rules loaded: 1", result.stdout)

            data = json.loads((Path(tmp) / "analysis.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in data["findings"]}
            self.assertIn("CUSTOM-001", rule_ids)
            self.assertEqual(data["custom_rules_loaded"], 1)

    def test_missing_input_file_returns_nonzero(self):
        result = run_tool("samples/does_not_exist.txt")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
