# Design Notes: Security Baseline Compliance Auditor

## Purpose

The tool evaluates exported Linux-style configuration artifacts against a
transparent baseline without requiring privileged access or modifying a target.

## Version 2.0.0 Architecture

The original single-file implementation was divided into focused modules:

- `parsers.py`: text, key/value, integer, CSV, and permission parsing
- `profiles.py`: external profile resolution and validation
- `checks.py`: profile-driven evaluation and specialized checks
- `scoring.py`: weighted summary and severity-threshold logic
- `reporters.py`: JSON, CSV, text, and HTML output
- `cli.py`: command-line arguments and exit behavior
- `models.py`: shared immutable data classes

`baseline_auditor.py` remains as a thin compatibility entry point, so the
original execution command still works.

## External Profile Design

The default baseline now resides in `profiles/default.json`. Key/value rules
declare:

- Check ID
- Artifact key
- Comparison operator
- Expected value or numeric threshold
- Severity
- Pass and fail titles
- Rationale
- Recommendation

This allows thresholds and expected values to be changed without editing Python
source code. Specialized firewall and file-permission checks also take their
titles, severities, patterns, and recommendations from the profile.

The profile is intentionally identified as a custom educational baseline.
Formal CIS or NIST mappings are deferred until each rule can be independently
validated against the applicable source requirement.

## Input Validation

Malformed numeric values now produce explicit failed findings rather than being
silently treated as absent. Unparseable key/value lines and incomplete
permission CSV records also produce Input Validation findings.

The parser continues processing valid records so one malformed entry does not
prevent the remainder of the assessment.

## Exit Behavior

Report-only use remains backward compatible and returns zero after a completed
audit. Users may enable `--fail-on-findings` and select a minimum severity with
`--fail-level`. This supports CI/CD workflows without forcing nonzero exits on
interactive users.

## Tests

The standard-library `unittest` suite validates:

- Secure and insecure reference datasets
- Expected severity totals and scores
- Octal and symbolic permission parsing
- Malformed values and rows
- Missing target behavior
- Output generation
- Severity-aware exit codes
- Profile customization without Python edits

## Scoring

The weighted scoring method preserves the original behavior. Failed findings
use profile-defined severity weights, while passed checks use the profile's
`pass_weight`. The score is a triage indicator rather than a formal compliance
certification or validated organizational risk score.

## Remaining Limitations

The tool still analyzes exported artifacts rather than live effective
configuration. It does not yet include validated CIS/NIST profiles, live
collection, Windows, cloud, container, or Kubernetes checks.
