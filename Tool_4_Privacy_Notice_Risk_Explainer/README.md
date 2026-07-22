# Tool 4: Privacy Notice Risk Explainer

## Overview

Privacy Notice Risk Explainer is a local, rule-based tool that reviews privacy notices, consent statements, application permission disclosures, and data-use language. It highlights privacy and trust concerns in plain language so users, analysts, or reviewers can better understand what a notice may imply.

This tool supports the Tool 4 theme: Human, Privacy, & Trust-Centered Security.

## What Problem This Solves

Privacy notices are often difficult for users to understand. Important details about data collection, sharing, retention, advertising, profiling, and sensitive data may be buried in broad or vague language.

This tool helps by converting privacy notice language into a structured report with:

- Risk level
- Risk score
- Plain-language findings
- Evidence snippets
- Suggested improvements
- Readability indicators
- JSON, text, HTML, and CSV reports

## Safety and Scope

This tool performs static text analysis only. It does not connect to websites, collect user data, use external APIs, or provide legal advice. It does not determine regulatory compliance. Its purpose is to support privacy and security review.

## Requirements

Python 3.10 or newer is recommended.

No third-party Python packages are required.

## Basic Usage

Run against a sample low-risk notice:

```bash
python3 privacy_notice_risk_explainer.py samples/low_risk_notice.txt -o output/low-risk
```

Run against a high-risk notice:

```bash
python3 privacy_notice_risk_explainer.py samples/high_risk_notice.txt -o output/high-risk
```

Run against an ambiguous notice:

```bash
python3 privacy_notice_risk_explainer.py samples/ambiguous_notice.txt -o output/ambiguous
```

Run against an app-permissions notice:

```bash
python3 privacy_notice_risk_explainer.py samples/app_permissions_notice.txt -o output/app-permissions
```

Write only JSON output:

```bash
python3 privacy_notice_risk_explainer.py samples/high_risk_notice.txt -f json -o output/json-only
```

Show the version:

```bash
python3 privacy_notice_risk_explainer.py --version
```

## Output Files

By default, the tool writes:

- `analysis.json`
- `summary.txt`
- `report.html`
- `findings.csv`

## Example Output

```text
Privacy Notice Risk Explainer v1.0.0
Source: samples/high_risk_notice.txt
Risk level: CRITICAL
Risk score: 38
Findings: 10
Readability: Difficult (grade 14.3)

Top findings:
- [HIGH] Precise location or geolocation collection
- [CRITICAL] Biometric information collection
- [HIGH] Contacts, photos, or device-content access
- [MEDIUM] Device identifiers or tracking identifiers
- [HIGH] Third-party sharing
```

## Testing

Run the full test suite:

```bash
python3 -m unittest discover -s tests -v
```

Expected result:

```text
Ran 6 tests
OK
```

## Design Summary

The tool uses a local rule engine. Each rule contains:

- Rule ID
- Title
- Severity
- Category
- Regex patterns
- Plain-language explanation
- Suggested improvement

The tool scans the input text for rule matches, records one finding per matched rule, calculates a severity-weighted score, assigns an overall risk level, calculates basic readability metrics, and writes reports.

## Limitations

This is a rule-based reviewer. It can miss issues that use unusual wording. It can also flag language without understanding full legal context. Results should be reviewed by a human.

## Version

Current version: 1.0.0
