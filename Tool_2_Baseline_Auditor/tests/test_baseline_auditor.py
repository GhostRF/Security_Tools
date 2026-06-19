"""Automated regression tests for Security Baseline Compliance Auditor."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIR))

from baseline_auditor_core.checks import run_audit  # noqa: E402
from baseline_auditor_core.parsers import is_world_writable_mode  # noqa: E402
from baseline_auditor_core.profiles import load_profile  # noqa: E402
from baseline_auditor_core.scoring import summarize  # noqa: E402


class BaselineAuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_profile(TOOL_DIR / "profiles" / "default.json")
        cls.script = TOOL_DIR / "baseline_auditor.py"

    def test_world_writable_permission_formats(self) -> None:
        cases = {
            "0777": True,
            "0666": True,
            "0644": False,
            "1777": True,
            "rwxrwxrwx": True,
            "-rw-rw-rw-": True,
            "drwxrwxrwx": True,
            "-rw-r--r--": False,
            "drwxr-xr-x": False,
        }
        for mode, expected in cases.items():
            with self.subTest(mode=mode):
                self.assertEqual(
                    is_world_writable_mode(mode),
                    expected,
                )

    def test_secure_sample(self) -> None:
        findings = run_audit(
            TOOL_DIR / "samples" / "secure_linux",
            self.profile,
        )
        summary = summarize(findings, self.profile)
        self.assertEqual(summary["total_checks"], 15)
        self.assertEqual(summary["passed"], 15)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["compliance_score"], 100)

    def test_insecure_sample(self) -> None:
        findings = run_audit(
            TOOL_DIR / "samples" / "insecure_linux",
            self.profile,
        )
        summary = summarize(findings, self.profile)
        self.assertEqual(summary["total_checks"], 15)
        self.assertEqual(summary["passed"], 0)
        self.assertEqual(summary["failed"], 15)
        self.assertEqual(summary["critical"], 2)
        self.assertEqual(summary["high"], 4)
        self.assertEqual(summary["medium"], 6)
        self.assertEqual(summary["low"], 3)
        self.assertEqual(summary["compliance_score"], 0)

    def test_malformed_values_are_reported(self) -> None:
        findings = run_audit(
            TOOL_DIR / "samples" / "malformed_linux",
            self.profile,
        )
        titles = {finding.title for finding in findings}
        self.assertIn("Malformed value for MaxAuthTries", titles)
        self.assertIn("Malformed value for PASS_MAX_DAYS", titles)
        self.assertIn("Malformed value for PASS_MIN_LEN", titles)
        self.assertTrue(
            any(
                finding.category == "Input Validation"
                for finding in findings
            )
        )

    def test_missing_target_exit_code(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(self.script),
                "does-not-exist",
            ],
            cwd=TOOL_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("does not exist", completed.stdout)

    def test_secure_fail_on_findings_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(self.script),
                    "samples/secure_linux",
                    "-o",
                    output,
                    "--fail-on-findings",
                    "--fail-level",
                    "high",
                ],
                cwd=TOOL_DIR,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0)

    def test_insecure_fail_on_findings_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(self.script),
                    "samples/insecure_linux",
                    "-o",
                    output,
                    "--fail-on-findings",
                    "--fail-level",
                    "high",
                ],
                cwd=TOOL_DIR,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)

    def test_output_files_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(self.script),
                    "samples/secure_linux",
                    "-o",
                    output,
                ],
                cwd=TOOL_DIR,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            output_path = Path(output)
            for filename in (
                "findings.json",
                "findings.csv",
                "summary.txt",
                "report.html",
            ):
                self.assertTrue((output_path / filename).is_file())

            data = json.loads(
                (output_path / "findings.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(len(data), 15)

    def test_custom_profile_changes_threshold_without_code_edit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile_path = Path(temporary) / "custom.json"
            data = json.loads(
                (TOOL_DIR / "profiles" / "default.json").read_text(
                    encoding="utf-8"
                )
            )
            data["profile_id"] = "test-custom"
            data["name"] = "Test Custom Profile"
            ssh_rules = data["artifacts"]["sshd_config"]["rules"]
            max_auth_rule = next(
                rule
                for rule in ssh_rules
                if rule["check_id"] == "SSH-005"
            )
            max_auth_rule["maximum"] = 2
            profile_path.write_text(
                json.dumps(data),
                encoding="utf-8",
            )

            custom_profile = load_profile(profile_path)
            findings = run_audit(
                TOOL_DIR / "samples" / "secure_linux",
                custom_profile,
            )
            result = next(
                finding
                for finding in findings
                if finding.check_id == "SSH-005"
            )
            self.assertEqual(result.status, "FAIL")


if __name__ == "__main__":
    unittest.main()
