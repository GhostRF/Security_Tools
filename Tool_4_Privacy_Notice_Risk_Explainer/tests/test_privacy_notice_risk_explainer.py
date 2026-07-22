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
        self.assertIn("1.0.0", result.stdout)

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
            self.assertIn("Risk score: 6", result.stdout)
            self.assertIn("Findings: 2", result.stdout)

    def test_app_permissions_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool("samples/app_permissions_notice.txt", "-o", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Risk level: HIGH", result.stdout)
            self.assertIn("Risk score: 14", result.stdout)
            self.assertIn("Findings: 4", result.stdout)

    def test_missing_input_file_returns_nonzero(self):
        result = run_tool("samples/does_not_exist.txt")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
