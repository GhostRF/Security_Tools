# Security Baseline Compliance Auditor

## Overview

The Security Baseline Compliance Auditor is a defensive systems and infrastructure security tool that analyzes exported Linux-style configuration artifacts against a transparent security baseline. The tool is designed to help analysts, system administrators, students, and security teams quickly identify common configuration weaknesses in system hardening, SSH configuration, password policy, kernel/network settings, firewall posture, and file permissions.

## Problem Definition

Security teams often need to evaluate whether systems are configured according to an expected hardening baseline. In many environments, especially small organizations, lab systems, development systems, and student environments, there may not be a centralized compliance scanning platform available. Even when enterprise tools exist, analysts still need lightweight ways to review exported configuration artifacts, explain findings, and reproduce results.

This tool addresses that problem by providing a portable Python-based baseline auditor that can run against sample or exported configuration files without requiring privileged access to the local system.

The tool supports both octal permission formats, such as `0777`, `0666`, and `1777`, and symbolic permission formats, such as `rwxrwxrwx`, `-rw-rw-rw-`, and `drwxrwxrwx`. This makes the file-permission check more useful for realistic exported permission inventories because Linux permissions are commonly represented in both octal and symbolic formats.

## What the Tool Checks

The current version evaluates the following Linux-style configuration artifacts:

- `sshd_config`
- `login.defs`
- `sysctl.conf`
- `firewall_status.txt`
- `file_permissions.csv`

The tool performs checks across these categories:

- SSH hardening
- Account and password policy
- Kernel and network hardening
- Host firewall status
- File permission inventory review

## Current Baseline Checks

The current version includes 15 checks:

- SSH root login restricted
- SSH password authentication disabled
- SSH empty passwords disabled
- SSH X11 forwarding disabled
- SSH authentication retries limited
- Password maximum age configured
- Password minimum age configured
- Password minimum length configured
- Password expiration warning configured
- IP forwarding disabled
- ICMP redirects disabled
- Sending ICMP redirects disabled
- TCP SYN cookies enabled
- Host firewall appears enabled
- No world-writable files found in the file permission inventory

## Repository Structure

```text
Tool_2_Baseline_Auditor/
├── baseline_auditor.py
├── README.md
├── requirements.txt
├── samples/
│   ├── secure_linux/
│   └── insecure_linux/
└── docs/
    ├── DESIGN_NOTES.md
    └── AI_USAGE.md
```

## Requirements

The tool uses Python 3 and the Python standard library only.

No third-party packages are required.

## Setup

Clone the repository and move into the tool directory:

```bash
git clone https://github.com/GhostRF/Security_Tools.git
cd Security_Tools/Tool_2_Baseline_Auditor
```

Optional syntax check:

```bash
python3 -m py_compile baseline_auditor.py
```

## Usage

Run the tool against the secure sample:

```bash
python3 baseline_auditor.py samples/secure_linux -o output_secure
```

Run the tool against the insecure sample:

```bash
python3 baseline_auditor.py samples/insecure_linux -o output_insecure
```

Check the tool version:

```bash
python3 baseline_auditor.py --version
```

## Expected Results

Secure sample expected result:

```text
Security Baseline Compliance Auditor v1.1.0
Baseline checks run: 15
Passed: 15
Failed: 0
Compliance score: 100%
Critical findings: 0
High findings: 0
Medium findings: 0
Low findings: 0
```

Insecure sample expected result:

```text
Security Baseline Compliance Auditor v1.1.0
Baseline checks run: 15
Passed: 0
Failed: 15
Compliance score: 0%
Critical findings: 2
High findings: 4
Medium findings: 6
Low findings: 3
```

## Output Files

The tool writes the following files to the selected output directory:

```text
findings.json
findings.csv
summary.txt
report.html
```

## Known Limitations

This tool does not directly scan the live operating system. It analyzes exported configuration artifacts. This design improves safety and reproducibility, but it also means the quality of the results depends on the accuracy and completeness of the provided input files.

The current version focuses on Linux-style configuration files and does not yet support Windows baselines, cloud configuration exports, container security checks, Kubernetes manifests, or direct CIS Benchmark mapping.

## Safety and Ethics

This tool is defensive and does not exploit systems, modify configuration files, or perform intrusive scanning. It is intended for authorized assessment of exported configuration artifacts.
