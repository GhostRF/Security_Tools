# Security Baseline Compliance Auditor

## Overview

The Security Baseline Compliance Auditor is a defensive systems and infrastructure security tool that analyzes exported Linux-style configuration artifacts against a transparent security baseline. The tool is designed to help analysts, system administrators, students, and security teams quickly identify common configuration weaknesses in system hardening, SSH configuration, password policy, kernel/network settings, firewall posture, and file permissions.

## Problem Definition

Security teams often need to evaluate whether systems are configured according to an expected hardening baseline. In many environments, especially small organizations, lab systems, development systems, and student environments, there may not be a centralized compliance scanning platform available. Even when enterprise tools exist, analysts still need lightweight ways to review exported configuration artifacts, explain findings, and reproduce results.

This tool addresses that problem by providing a portable Python-based baseline auditor that can run against sample or exported configuration files without requiring privileged access to the local system.

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
