# Design Notes: Security Baseline Compliance Auditor

## Purpose

The tool provides a lightweight way to evaluate exported Linux-style configuration artifacts against a transparent security baseline. It is intended for defensive assessment, education, and reproducible peer review.

## Problem Addressed

Many organizations and small teams need to assess system hardening but may not have access to enterprise compliance scanners or centralized configuration management platforms. Even when those tools exist, analysts still need a simple way to review configuration artifacts, explain findings, and produce repeatable evidence.

This tool addresses that gap by analyzing exported configuration files rather than directly scanning or modifying a live system. This makes the tool safer and easier for classmates to reproduce.

## Design Goals

The tool was designed around the following goals:

1. Reproducibility
   - Other students should be able to clone the repository, run the tool, and reproduce the expected results using the included sample data.

2. Safety
   - The tool does not exploit systems, modify configuration files, require privileged access, or perform intrusive scanning.

3. Transparency
   - Each check has a visible rule, check ID, evidence field, rationale, and recommendation.

4. Portability
   - The tool uses Python 3 and the standard library only.

## Input Design

The tool analyzes a target directory containing exported configuration artifacts. The current version expects files such as:

- sshd_config
- login.defs
- sysctl.conf
- firewall_status.txt
- file_permissions.csv

This approach allows the tool to run against both sample data and real exported system configuration files.

## Baseline Categories

The current version includes checks across five categories:

- SSH hardening
- Account and password policy
- Kernel and network hardening
- Host firewall status
- File permissions

## Output Design

The tool generates four output files:

- findings.json
- findings.csv
- summary.txt
- report.html

The JSON and CSV outputs support machine-readable review and follow-on analysis. The HTML report provides a human-readable summary for screenshots, demonstrations, and analyst review.

## Scoring Methodology

The compliance score is a simple weighted triage indicator. Failed checks subtract weighted points based on severity:

- Critical: 25
- High: 15
- Medium: 8
- Low: 3

The score is intended to help prioritize review. It is not a formal compliance certification, validated risk score, or replacement for a full security assessment.

## Test Results

The tool was tested using two included sample datasets.

Secure sample result:

```text
Baseline checks run: 15
Passed: 15
Failed: 0
Compliance score: 100%
Critical findings: 0
High findings: 0
Medium findings: 0
Low findings: 0
```
Insecure sample result:
```text
Baseline checks run: 15
Passed: 0
Failed: 15
Compliance score: 0%
Critical findings: 2
High findings: 4
Medium findings: 6
Low findings: 3
```
These tests demonstrate that the tool can distinguish between a baseline-aligned sample configuration and an intentionally insecure sample configuration.

## Known Limitations

The tool does not directly collect settings from a live host. It depends on exported configuration artifacts provided by the user.

The current version focuses on Linux-style configuration files. It does not yet support Windows baselines, cloud configuration exports, Kubernetes manifests, container runtime configuration, or direct CIS Benchmark mapping.

The current checks are intentionally simple and transparent. They should be expanded and validated before operational use.

The compliance score is manually weighted and should be treated as a triage aid, not a formal measure of organizational risk.

## Future Work

Future improvements could include:

YAML-based external rule definitions
CIS Benchmark mapping
Windows baseline checks
Container and Kubernetes checks
Cloud configuration checks
Live local collection mode
More detailed scoring options
Better HTML styling and charts
Automated test cases
Additional sample datasets
Ethical and Operational Considerations

This tool is defensive and non-intrusive. It should only be used to assess systems or configuration artifacts that the user is authorized to review. The tool does not make configuration changes, exploit vulnerabilities, or perform active network scanning.
