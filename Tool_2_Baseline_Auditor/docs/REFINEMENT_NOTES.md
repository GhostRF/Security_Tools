# Tool 2 Refinement Notes

## Feedback Received

Three peer reviews consistently identified the tool as reproducible, relevant,
lightweight, and easy to use. The main improvement themes were:

- External rule files and selectable profiles
- Automated tests
- Better malformed-input handling
- CI/CD-friendly exit codes
- Modular code organization
- Broader platform and framework coverage

## Feedback Accepted and Implemented

### External profiles

The original hardcoded rule definitions were moved to
`profiles/default.json`. Users can change supported thresholds and expected
values or provide a different profile without editing Python source.

### Automated testing

A standard-library test suite now validates the known-good and known-bad
samples, malformed values, permission parsing, output generation, profile
customization, target validation, and exit behavior.

### Malformed input

Malformed numeric settings, malformed configuration lines, missing CSV
columns, and incomplete CSV rows now generate visible findings rather than
being silently skipped.

### Exit codes

The new `--fail-on-findings` and `--fail-level` options allow automation to
return exit code 1 when findings meet a selected severity threshold.

### Modular structure

Parsing, profile handling, checks, scoring, reporting, and command-line
behavior were separated into focused modules. The original command remains
available through a compatibility entry point.

## Feedback Partially Accepted

Peer reviewers suggested formal CIS and NIST profiles. Version 2.0.0 implements
the profile framework but does not claim formal mappings. Accurate mappings
require validation against authoritative control and benchmark text and should
not be inferred from similar hardening checks.

## Feedback Deferred

Windows, cloud, container, Kubernetes, and live local collection support were
deferred because they require additional parsers, collectors, platform-specific
test environments, and scope beyond this refinement cycle.

## Lessons Learned

Reproducibility requires more than sample data. Automated tests, explicit input
validation, stable exit behavior, and externally configurable rules make the
tool easier to maintain and safer to use in repeatable workflows.
