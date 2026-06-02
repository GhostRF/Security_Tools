#!/usr/bin/env python3
"""
Security Baseline Compliance Auditor

A defensive systems and infrastructure security tool that analyzes exported
Linux-style configuration artifacts against a transparent security baseline.

This tool is designed for reproducible security baseline assessment using
sample or exported configuration files. It does not require privileged access
to the local host and does not modify any system settings.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


@dataclass
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    category: str
    evidence: str
    rationale: str
    recommendation: str


def read_text_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_key_value_config(text: str) -> Dict[str, str]:
    """
    Parse simple key/value configuration files such as sshd_config, login.defs,
    and sysctl.conf.

    Supports lines such as:
        PermitRootLogin no
        PASS_MAX_DAYS 90
        net.ipv4.ip_forward = 0
    """
    config: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if not line:
            continue

        if "=" in line:
            key, value = line.split("=", 1)
            config[key.strip().lower()] = value.strip()
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].strip().lower()] = parts[1].strip()

    return config


def get_value(config: Dict[str, str], key: str) -> Optional[str]:
    return config.get(key.lower())


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


def check_sshd_config(target_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    sshd_path = target_dir / "sshd_config"
    text = read_text_file(sshd_path)
    config = parse_key_value_config(text)

    category = "SSH Hardening"

    if not text:
        findings.append(
            fail_finding(
                "SSH-000",
                "sshd_config file is missing",
                "high",
                category,
                "sshd_config was not found in the target directory.",
                "SSH configuration could not be assessed without the exported sshd_config file.",
                "Export sshd_config from the target system and include it in the assessment directory.",
            )
        )
        return findings

    value = get_value(config, "PermitRootLogin")
    if value and value.lower() in {"no", "prohibit-password", "forced-commands-only"}:
        findings.append(
            pass_finding(
                "SSH-001",
                "SSH root login is restricted",
                category,
                f"PermitRootLogin {value}",
                "Restricting direct root login reduces the risk of direct privileged remote access.",
                "Keep PermitRootLogin set to no or another restrictive value appropriate for the environment.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "SSH-001",
                "SSH root login is not restricted",
                "critical",
                category,
                f"PermitRootLogin {value if value else 'not set'}",
                "Direct root login over SSH increases the impact of credential compromise and remote brute-force attempts.",
                "Set PermitRootLogin no unless a documented operational exception exists.",
            )
        )

    value = get_value(config, "PasswordAuthentication")
    if value and value.lower() == "no":
        findings.append(
            pass_finding(
                "SSH-002",
                "SSH password authentication is disabled",
                category,
                f"PasswordAuthentication {value}",
                "Disabling password authentication reduces exposure to password guessing and credential-stuffing attacks.",
                "Continue using key-based authentication where operationally feasible.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "SSH-002",
                "SSH password authentication is enabled or not explicitly disabled",
                "high",
                category,
                f"PasswordAuthentication {value if value else 'not set'}",
                "Password-based SSH access can increase brute-force and credential-stuffing risk.",
                "Set PasswordAuthentication no if key-based authentication is supported by the environment.",
            )
        )

    value = get_value(config, "PermitEmptyPasswords")
    if value and value.lower() == "no":
        findings.append(
            pass_finding(
                "SSH-003",
                "SSH empty passwords are disabled",
                category,
                f"PermitEmptyPasswords {value}",
                "Rejecting empty passwords prevents remote login for accounts with blank passwords.",
                "Keep PermitEmptyPasswords set to no.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "SSH-003",
                "SSH empty password protection is missing",
                "critical",
                category,
                f"PermitEmptyPasswords {value if value else 'not set'}",
                "Allowing empty passwords creates a severe remote access risk.",
                "Set PermitEmptyPasswords no.",
            )
        )

    value = get_value(config, "X11Forwarding")
    if value and value.lower() == "no":
        findings.append(
            pass_finding(
                "SSH-004",
                "SSH X11 forwarding is disabled",
                category,
                f"X11Forwarding {value}",
                "Disabling X11 forwarding reduces unnecessary remote session exposure.",
                "Keep X11Forwarding disabled unless there is a documented operational requirement.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "SSH-004",
                "SSH X11 forwarding is enabled or not explicitly disabled",
                "medium",
                category,
                f"X11Forwarding {value if value else 'not set'}",
                "X11 forwarding is often unnecessary on hardened servers and may increase attack surface.",
                "Set X11Forwarding no unless required.",
            )
        )

    value = get_value(config, "MaxAuthTries")
    try:
        max_auth_tries = int(value) if value else None
    except ValueError:
        max_auth_tries = None

    if max_auth_tries is not None and max_auth_tries <= 4:
        findings.append(
            pass_finding(
                "SSH-005",
                "SSH authentication retries are limited",
                category,
                f"MaxAuthTries {value}",
                "Limiting authentication attempts reduces brute-force opportunity per connection.",
                "Keep MaxAuthTries at 4 or lower unless operational needs require otherwise.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "SSH-005",
                "SSH authentication retries are not tightly limited",
                "medium",
                category,
                f"MaxAuthTries {value if value else 'not set'}",
                "A high number of authentication retries can increase brute-force opportunity.",
                "Set MaxAuthTries 4 or lower.",
            )
        )

    return findings


def check_login_defs(target_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    path = target_dir / "login.defs"
    text = read_text_file(path)
    config = parse_key_value_config(text)
    category = "Account and Password Policy"

    if not text:
        findings.append(
            fail_finding(
                "AUTH-000",
                "login.defs file is missing",
                "medium",
                category,
                "login.defs was not found in the target directory.",
                "Password aging policy could not be assessed without login.defs.",
                "Export login.defs from the target system and include it in the assessment directory.",
            )
        )
        return findings

    max_days = parse_int(get_value(config, "PASS_MAX_DAYS"))
    if max_days is not None and 1 <= max_days <= 90:
        findings.append(
            pass_finding(
                "AUTH-001",
                "Password maximum age is configured",
                category,
                f"PASS_MAX_DAYS {max_days}",
                "Password aging can reduce the long-term exposure of compromised credentials.",
                "Keep PASS_MAX_DAYS aligned with organizational policy.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "AUTH-001",
                "Password maximum age is weak or missing",
                "medium",
                category,
                f"PASS_MAX_DAYS {max_days if max_days is not None else 'not set'}",
                "Missing or excessive password age values can increase credential exposure duration.",
                "Set PASS_MAX_DAYS to a value aligned with organizational policy, such as 90 days where appropriate.",
            )
        )

    min_days = parse_int(get_value(config, "PASS_MIN_DAYS"))
    if min_days is not None and min_days >= 1:
        findings.append(
            pass_finding(
                "AUTH-002",
                "Password minimum age is configured",
                category,
                f"PASS_MIN_DAYS {min_days}",
                "A minimum password age can reduce rapid password cycling to bypass history controls.",
                "Keep PASS_MIN_DAYS set according to organizational policy.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "AUTH-002",
                "Password minimum age is missing or too low",
                "low",
                category,
                f"PASS_MIN_DAYS {min_days if min_days is not None else 'not set'}",
                "Very low minimum password age values may allow users to cycle passwords quickly.",
                "Set PASS_MIN_DAYS to at least 1 if consistent with organizational policy.",
            )
        )

    min_len = parse_int(get_value(config, "PASS_MIN_LEN"))
    if min_len is not None and min_len >= 12:
        findings.append(
            pass_finding(
                "AUTH-003",
                "Password minimum length is configured",
                category,
                f"PASS_MIN_LEN {min_len}",
                "Longer passwords generally improve resistance to guessing and cracking attacks.",
                "Keep password length requirements aligned with organizational authentication policy.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "AUTH-003",
                "Password minimum length is weak or missing",
                "medium",
                category,
                f"PASS_MIN_LEN {min_len if min_len is not None else 'not set'}",
                "Short passwords are easier to guess or crack if password hashes are exposed.",
                "Set PASS_MIN_LEN to 12 or greater if compatible with the authentication stack.",
            )
        )

    warn_age = parse_int(get_value(config, "PASS_WARN_AGE"))
    if warn_age is not None and warn_age >= 7:
        findings.append(
            pass_finding(
                "AUTH-004",
                "Password expiration warning is configured",
                category,
                f"PASS_WARN_AGE {warn_age}",
                "Warning users before password expiration reduces operational disruption.",
                "Keep PASS_WARN_AGE at 7 or more days if password aging is used.",
            )
        )
    else:
        findings.append(
            fail_finding(
                "AUTH-004",
                "Password expiration warning is missing or too short",
                "low",
                category,
                f"PASS_WARN_AGE {warn_age if warn_age is not None else 'not set'}",
                "Users may not receive adequate warning before password expiration.",
                "Set PASS_WARN_AGE to 7 or greater if password aging is used.",
            )
        )

    return findings


def check_sysctl(target_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    path = target_dir / "sysctl.conf"
    text = read_text_file(path)
    config = parse_key_value_config(text)
    category = "Kernel and Network Hardening"

    if not text:
        findings.append(
            fail_finding(
                "SYSCTL-000",
                "sysctl.conf file is missing",
                "medium",
                category,
                "sysctl.conf was not found in the target directory.",
                "Kernel and network hardening values could not be assessed.",
                "Export sysctl.conf or equivalent sysctl output from the target system.",
            )
        )
        return findings

    expected_values = [
        (
            "SYSCTL-001",
            "net.ipv4.ip_forward",
            "0",
            "IP forwarding is disabled",
            "IP forwarding can turn a host into a router and may increase lateral movement or pivoting risk.",
            "Set net.ipv4.ip_forward = 0 unless routing is explicitly required.",
            "high",
        ),
        (
            "SYSCTL-002",
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "ICMP redirects are disabled",
            "Accepting redirects can allow malicious routing manipulation in some environments.",
            "Set net.ipv4.conf.all.accept_redirects = 0.",
            "medium",
        ),
        (
            "SYSCTL-003",
            "net.ipv4.conf.all.send_redirects",
            "0",
            "Sending ICMP redirects is disabled",
            "Sending redirects is generally unnecessary for hardened non-router systems.",
            "Set net.ipv4.conf.all.send_redirects = 0.",
            "medium",
        ),
        (
            "SYSCTL-004",
            "net.ipv4.tcp_syncookies",
            "1",
            "TCP SYN cookies are enabled",
            "SYN cookies can help improve resilience to SYN flood conditions.",
            "Set net.ipv4.tcp_syncookies = 1.",
            "low",
        ),
    ]

    for check_id, key, expected, title, rationale, recommendation, severity in expected_values:
        actual = get_value(config, key)
        if actual == expected:
            findings.append(
                pass_finding(
                    check_id,
                    title,
                    category,
                    f"{key} = {actual}",
                    rationale,
                    recommendation,
                )
            )
        else:
            findings.append(
                fail_finding(
                    check_id,
                    title,
                    severity,
                    category,
                    f"{key} = {actual if actual is not None else 'not set'}",
                    rationale,
                    recommendation,
                )
            )

    return findings


def check_firewall_status(target_dir: Path) -> List[Finding]:
    path = target_dir / "firewall_status.txt"
    text = read_text_file(path)
    category = "Firewall"

    if not text:
        return [
            fail_finding(
                "FW-001",
                "Firewall status export is missing",
                "medium",
                category,
                "firewall_status.txt was not found.",
                "The tool could not determine whether a host firewall appears to be enabled.",
                "Include a firewall status export such as ufw status, firewall-cmd state, or equivalent output.",
            )
        ]

    lower = text.lower()
    enabled_patterns = [
        "status: active",
        "active",
        "running",
        "enabled",
    ]
    disabled_patterns = [
        "inactive",
        "disabled",
        "not running",
        "stopped",
    ]

    if any(pattern in lower for pattern in enabled_patterns) and not any(pattern in lower for pattern in disabled_patterns):
        return [
            pass_finding(
                "FW-001",
                "Host firewall appears enabled",
                category,
                text.strip()[:200],
                "A host firewall can reduce exposed services and limit inbound traffic.",
                "Keep host firewall policy enabled and review allowed services regularly.",
            )
        ]

    return [
        fail_finding(
            "FW-001",
            "Host firewall does not appear enabled",
            "high",
            category,
            text.strip()[:200],
            "A disabled host firewall may increase exposed attack surface.",
            "Enable and configure the host firewall according to system role and organizational policy.",
        )
    ]


def check_file_permissions(target_dir: Path) -> List[Finding]:
    path = target_dir / "file_permissions.csv"
    category = "File Permissions"
    findings: List[Finding] = []

    if not path.exists():
        return [
            fail_finding(
                "FILE-000",
                "File permission inventory is missing",
                "low",
                category,
                "file_permissions.csv was not found.",
                "World-writable file checks require an exported file permission inventory.",
                "Include a CSV with columns path, owner, group, mode.",
            )
        ]

    rows: List[Dict[str, str]] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    risky_rows = []
    for row in rows:
        mode = str(row.get("mode", "")).strip()
        file_path = str(row.get("path", "")).strip()
        if is_world_writable_mode(mode):
            risky_rows.append((file_path, mode))

    if not risky_rows:
        findings.append(
            pass_finding(
                "FILE-001",
                "No world-writable files found in inventory",
                category,
                f"Reviewed {len(rows)} file permission records.",
                "World-writable files can allow unauthorized modification if located in sensitive paths.",
                "Continue reviewing file permissions for sensitive directories.",
            )
        )
    else:
        evidence = "; ".join(f"{p} ({m})" for p, m in risky_rows[:10])
        findings.append(
            fail_finding(
                "FILE-001",
                "World-writable files found in inventory",
                "high",
                category,
                evidence,
                "World-writable files can allow unauthorized modification and may support privilege escalation or persistence.",
                "Remove world-writable permissions unless explicitly required and documented.",
            )
        )

    return findings


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def is_world_writable_mode(mode: str) -> bool:
    """
    Supports octal modes such as 777, 0777, 666, 0666.
    """
    clean = mode.strip()
    if not re.fullmatch(r"0?[0-7]{3,4}", clean):
        return False
    last_digit = int(clean[-1])
    return bool(last_digit & 0o2)


def run_audit(target_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_sshd_config(target_dir))
    findings.extend(check_login_defs(target_dir))
    findings.extend(check_sysctl(target_dir))
    findings.extend(check_firewall_status(target_dir))
    findings.extend(check_file_permissions(target_dir))
    return findings


def compliance_score(findings: List[Finding]) -> int:
    applicable = [f for f in findings if f.status in {"PASS", "FAIL"}]
    failed = [f for f in applicable if f.status == "FAIL"]

    if not applicable:
        return 0

    total_penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in failed)
    max_penalty = sum(
        SEVERITY_WEIGHTS.get(f.severity, 0) if f.status == "FAIL" else 10
        for f in applicable
    )

    if max_penalty <= 0:
        return 100

    score = 100 - int((total_penalty / max_penalty) * 100)
    return max(0, min(100, score))


def summarize(findings: List[Finding]) -> Dict[str, int]:
    summary = {
        "total_checks": len(findings),
        "passed": sum(1 for f in findings if f.status == "PASS"),
        "failed": sum(1 for f in findings if f.status == "FAIL"),
        "critical": sum(1 for f in findings if f.status == "FAIL" and f.severity == "critical"),
        "high": sum(1 for f in findings if f.status == "FAIL" and f.severity == "high"),
        "medium": sum(1 for f in findings if f.status == "FAIL" and f.severity == "medium"),
        "low": sum(1 for f in findings if f.status == "FAIL" and f.severity == "low"),
    }
    summary["compliance_score"] = compliance_score(findings)
    return summary


def write_json(findings: List[Finding], out_dir: Path) -> None:
    (out_dir / "findings.json").write_text(
        json.dumps([asdict(f) for f in findings], indent=2),
        encoding="utf-8",
    )


def write_csv(findings: List[Finding], out_dir: Path) -> None:
    csv_path = out_dir / "findings.csv"
    fieldnames = [
        "check_id",
        "title",
        "status",
        "severity",
        "category",
        "evidence",
        "rationale",
        "recommendation",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def write_summary(findings: List[Finding], out_dir: Path) -> None:
    summary = summarize(findings)
    lines = [
        f"Baseline checks run: {summary['total_checks']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Compliance score: {summary['compliance_score']}%",
        f"Critical findings: {summary['critical']}",
        f"High findings: {summary['high']}",
        f"Medium findings: {summary['medium']}",
        f"Low findings: {summary['low']}",
    ]

    (out_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_html(findings: List[Finding], out_dir: Path) -> None:
    summary = summarize(findings)

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.check_id)}</td>"
            f"<td>{html.escape(finding.status)}</td>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.evidence)}</td>"
            f"<td>{html.escape(finding.recommendation)}</td>"
            "</tr>"
        )

    document = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Security Baseline Compliance Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; vertical-align: top; }}
    th {{ background: #f2f2f2; }}
    .score {{ font-size: 1.4rem; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Security Baseline Compliance Report</h1>
  <p class="score">Compliance Score: {summary['compliance_score']}%</p>
  <ul>
    <li>Baseline checks run: {summary['total_checks']}</li>
    <li>Passed: {summary['passed']}</li>
    <li>Failed: {summary['failed']}</li>
    <li>Critical findings: {summary['critical']}</li>
    <li>High findings: {summary['high']}</li>
    <li>Medium findings: {summary['medium']}</li>
    <li>Low findings: {summary['low']}</li>
  </ul>
  <table>
    <tr>
      <th>Check ID</th>
      <th>Status</th>
      <th>Severity</th>
      <th>Category</th>
      <th>Title</th>
      <th>Evidence</th>
      <th>Recommendation</th>
    </tr>
    {''.join(rows)}
  </table>
</body>
</html>
"""
    (out_dir / "report.html").write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit exported Linux configuration artifacts against a transparent security baseline."
    )
    parser.add_argument("target", help="Directory containing exported configuration artifacts")
    parser.add_argument("-o", "--output", default="baseline_auditor_output", help="Output directory")
    args = parser.parse_args()

    target_dir = Path(args.target)
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"[ERROR] Target directory does not exist or is not a directory: {target_dir}")
        return 2

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = run_audit(target_dir)
    summary = summarize(findings)

    write_json(findings, out_dir)
    write_csv(findings, out_dir)
    write_summary(findings, out_dir)
    write_html(findings, out_dir)

    print(f"Baseline checks run: {summary['total_checks']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Compliance score: {summary['compliance_score']}%")
    print(f"Critical findings: {summary['critical']}")
    print(f"High findings: {summary['high']}")
    print(f"Medium findings: {summary['medium']}")
    print(f"Low findings: {summary['low']}")
    print(f"Output written to: {out_dir.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
