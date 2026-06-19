# Security Baseline Compliance Auditor

## Overview

The Security Baseline Compliance Auditor is a defensive systems and
infrastructure security tool that analyzes exported Linux-style configuration
artifacts against a transparent baseline profile. It does not scan a live host,
require privileged access, or modify system settings.

The tool was developed for CSC-842 Security Tool Development under the
Systems, Software, & Infrastructure Security theme.

## Version 2.0.0 Refinement

Version 2.0.0 incorporates peer feedback by adding:

- External JSON baseline profiles
- Profile selection through `--profile`
- Automated standard-library regression tests
- Optional CI/CD-friendly severity exit codes
- Explicit malformed-input findings
- Modular separation of parsing, checks, scoring, reporting, profiles, and CLI
- A malformed sample dataset
- A GitHub Actions test workflow
- Rationale in the HTML report

The bundled profile remains a custom educational baseline. It is not presented
as a formal CIS Benchmark or NIST certification profile.

## Current Checks

The bundled default profile performs 15 checks across:

- SSH hardening
- Account and password policy
- Kernel and network hardening
- Host firewall status
- File permissions

Input artifacts:

- `sshd_config`
- `login.defs`
- `sysctl.conf`
- `firewall_status.txt`
- `file_permissions.csv`

## Requirements

- Python 3.9 or later
- No third-party packages

## Quick Start

Run the secure sample:

```bash
python3 baseline_auditor.py samples/secure_linux -o output_secure
```

Run the insecure sample:

```bash
python3 baseline_auditor.py samples/insecure_linux -o output_insecure
```

Run the malformed-input sample:

```bash
python3 baseline_auditor.py samples/malformed_linux -o output_malformed
```

Check the version:

```bash
python3 baseline_auditor.py --version
```

List bundled profiles:

```bash
python3 baseline_auditor.py --list-profiles
```

## Profile Selection

The default profile is loaded from `profiles/default.json`:

```bash
python3 baseline_auditor.py samples/secure_linux \
  --profile default \
  -o output_secure
```

A custom profile path can also be supplied:

```bash
python3 baseline_auditor.py exported_host \
  --profile profiles/my-custom-profile.json \
  -o output_custom
```

See `profiles/README.md` for the profile schema and supported operators.

## Exit Codes

Normal report-only behavior remains the default:

- `0`: audit completed
- `2`: invalid target or profile
- `3`: runtime or output error

For CI/CD use, enable severity-aware failure behavior:

```bash
python3 baseline_auditor.py samples/insecure_linux \
  -o output_insecure \
  --fail-on-findings \
  --fail-level high
```

When `--fail-on-findings` is used:

- `0`: no failed finding meets the threshold
- `1`: at least one failed finding meets or exceeds the threshold

Supported thresholds are `low`, `medium`, `high`, and `critical`.

## Expected Sample Results

Secure sample:

```text
Baseline checks run: 15
Passed: 15
Failed: 0
Compliance score: 100%
```

Insecure sample:

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

The malformed sample intentionally demonstrates explicit findings for
unparseable values, malformed lines, and incomplete CSV records.

## Output Files

The tool writes:

- `findings.json`
- `findings.csv`
- `summary.txt`
- `report.html`

Each finding includes:

- Check ID
- Title
- Status
- Severity
- Category
- Evidence
- Rationale
- Recommendation

## Automated Tests

Run all tests:

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers secure and insecure samples, malformed inputs, octal and
symbolic permission formats, output generation, invalid target handling,
severity exit codes, and profile customization.

## Repository Structure

```text
Tool_2_Baseline_Auditor/
├── baseline_auditor.py
├── baseline_auditor_core/
│   ├── checks.py
│   ├── cli.py
│   ├── models.py
│   ├── parsers.py
│   ├── profiles.py
│   ├── reporters.py
│   └── scoring.py
├── profiles/
│   ├── default.json
│   └── README.md
├── samples/
│   ├── secure_linux/
│   ├── insecure_linux/
│   └── malformed_linux/
├── tests/
│   └── test_baseline_auditor.py
└── docs/
    ├── DESIGN_NOTES.md
    ├── AI_USAGE.md
    └── REFINEMENT_NOTES.md
```

## Known Limitations

- The tool evaluates exported artifacts rather than live effective settings.
- The default profile covers Linux-style artifacts only.
- The included profile is custom and is not a formal compliance certification.
- Firewall detection relies on common status strings.
- The tool does not yet support Windows, cloud, containers, Kubernetes, or live
  collection.

## Safety and Ethics

The tool is defensive and non-intrusive. It should only be used with
configuration artifacts the user is authorized to assess.
