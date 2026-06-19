# AI Usage Disclosure

## Overview

AI assistance was used during initial development and the version 2.0.0
refinement for planning, code structure, documentation drafting,
troubleshooting, and test design. The author reviewed and validated the final
implementation.

## Version 2.0.0 Assistance

AI assistance supported:

- Organizing peer feedback into actionable and deferred changes
- Designing the external JSON profile schema
- Refactoring the single script into focused modules
- Adding malformed-input handling
- Designing severity-aware exit behavior
- Drafting standard-library automated tests
- Updating documentation and refinement notes

## Accepted and Implemented Suggestions

After review and testing, the author accepted:

- External JSON rule profiles
- Modular separation of responsibilities
- Automated regression tests
- Optional nonzero exit codes for findings
- Explicit malformed-input findings
- A malformed sample dataset
- CI test automation

## Modified Suggestions

The peer recommendation referenced YAML or JSON. JSON was selected because it
is supported by the Python standard library and preserves the project's
no-third-party-dependency design.

Formal NIST and CIS profiles were not labeled or claimed in this release.
Instead, the tool now provides the profile mechanism needed for future mappings
after each rule is validated against authoritative requirements.

## Deferred Suggestions

Windows, cloud, container, Kubernetes, live collection, and validated
framework-specific profiles were deferred because they require additional
scope, source validation, and test data. They remain documented future work.

## Validation

Validation included:

- Python syntax compilation
- Secure, insecure, and malformed sample runs
- Automated unit and CLI tests
- Exit-code verification
- JSON, CSV, text, and HTML output generation
- Custom-profile threshold testing
- Octal and symbolic permission parsing tests

AI assistance did not replace human testing or responsibility for the submitted
tool.
