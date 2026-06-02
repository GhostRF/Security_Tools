# AI Usage Disclosure

## Overview

AI assistance was used during the development of the Security Baseline Compliance Auditor for brainstorming, code structure, documentation drafting, troubleshooting, and refinement planning.

The final tool was reviewed, tested, and validated by the author before submission.

## How AI Was Used

AI assistance was used to help:

- Identify tool ideas that fit the Systems, Software, & Infrastructure Security theme
- Select a tool concept that would be reproducible for peer review
- Draft the initial Python structure
- Create sample secure and insecure configuration artifacts
- Draft README and design documentation
- Troubleshoot local development workflow issues
- Improve clarity around limitations, scoring, and future work

## Human Review and Modification

The author reviewed and tested the generated code and documentation. The tool was run locally against both included sample datasets.

The author verified that the secure sample produced:

```text
Baseline checks run: 15
Passed: 15
Failed: 0
Compliance score: 100%
```

The author also reviewed the generated HTML reports to confirm that the findings, evidence, and recommendations appeared as expected.


## Validation Performed Included

Python syntax compilation using python3 -m py_compile
Running the tool against the secure sample dataset
Running the tool against the insecure sample dataset
Reviewing terminal output
Reviewing generated HTML reports
Confirming JSON, CSV, text, and HTML outputs were created
