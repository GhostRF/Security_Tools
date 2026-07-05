# AI Usage Disclosure

## AI Assistance

ChatGPT was used as a development assistant during this project.

AI assistance included:

- Brainstorming potential Tool 3 concepts
- Refining the problem statement
- Proposing the modular architecture
- Drafting portions of the Python implementation
- Drafting automated tests
- Suggesting safety controls
- Assisting with debugging
- Drafting documentation
- Reviewing terminal output and test results

## Representative Prompt Categories

Representative requests included:

- Propose novel tools for reverse engineering and adversary tradecraft.
- Design a non-executing multi-stage script and command analyzer.
- Implement safe Base64, hexadecimal, URL, and PowerShell decoding.
- Add bounded compression handling.
- Preserve transformation lineage and raw bytes.
- Add external rules and conservative ATT&CK hypotheses.
- Explain and document confidence scores.
- Diagnose failed automated tests from tracebacks.
- Add HTML escaping and forensic artifact verification.
- Create reproducible documentation and testing instructions.

## Evaluation and Modification

AI-generated suggestions were reviewed before acceptance.

Corrections and refinements made during development included:

- Correcting Bzip2 and XZ end-of-stream handling
- Adding explicit decompression-output limits
- Separating transformation confidence from finding confidence
- Requiring a written confidence basis for every tradecraft rule
- Correcting the `AnalysisResult` model to retain exact raw stage bytes
- Adding regression tests after defects were identified
- Adding maximum input-size, stage-count, per-stage output, and cumulative-output controls
- Adding transformation preallocation checks and bounded XZ decompression memory
- Preventing stale output artifacts from being mixed with a new analysis
- Reporting trailing gzip, zlib, Bzip2, and XZ data
- Correcting ambiguous Base64 and hexadecimal detection behavior
- Preserving validated binary URL-safe Base64 decoding
- Excluding Unicode replacement characters from printable-ratio calculations
- Adding execution provenance and auditable duplicate-stage warnings
- Correcting XZ terminology
- Avoiding unsupported claims of malicious intent
- Treating ATT&CK mappings as hypotheses rather than proof
- Keeping all included samples synthetic and harmless

## Validation Performed

I manually:

- Created and maintained the Git repository
- Entered and reviewed the source code
- Ran compilation checks
- Ran the complete automated test suite
- Examined failed-test tracebacks
- Applied and verified corrections
- Executed the documented samples
- Validated generated JSON
- Compared raw artifact hashes against recorded hashes
- Validated execution provenance and active resource-limit metadata
- Verified duplicate-stage suppression warnings
- Verified conservative Base64 and hexadecimal behavior
- Verified output-directory isolation
- Verified trailing compressed-data warnings
- Visually reviewed the HTML report
- Confirmed that decoded content was not executed

Version 1.0.0 includes 65 automated tests, all of which pass.

## Understanding and Original Contribution

I reviewed the architecture and understand the roles of:

- The command-line interface
- Transformation detectors
- Safe transformation functions
- Recursive pipeline
- Indicator extraction
- Tradecraft rules
- Data models
- Report generation

The final tool reflects iterative development, testing, debugging, and design decisions rather than an unmodified AI-generated submission.

## Limitations of AI Assistance

AI-generated suggestions can contain incorrect assumptions or defects.

Examples encountered during development included:

- Incorrect decompressor-state handling
- An overly restrictive plausibility check that temporarily rejected valid URL-safe Base64 binary data
- A stale automated-test expectation after command-line stage terminology changed
- An incomplete data-model update
- Shell-copying instructions that caused Markdown text to be interpreted as commands

Automated testing, source review, and manual validation were required to identify and correct these issues.
