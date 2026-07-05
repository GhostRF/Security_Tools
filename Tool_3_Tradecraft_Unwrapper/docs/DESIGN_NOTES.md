# Design Notes

## Design Objective

Tradecraft Unwrapper reconstructs supported transformations while preserving an auditable lineage and avoiding content execution.

The design prioritizes:

1. Safety
2. Reproducibility
3. Evidence preservation
4. Explainable findings
5. Extensibility
6. Minimal dependencies

## Processing Pipeline

The processing flow is:

~~~text
Input acquisition
-> byte-to-text preview
-> transformation detection
-> safe decoding or decompression
-> stage creation
-> recursive processing
-> indicator extraction
-> rule evaluation
-> report generation
~~~

## Entry Point and Command-Line Interface

`tradecraft_unwrapper.py` is the compatibility entry point and calls `tradecraft_unwrapper_core.cli.main()`.

The command-line interface:

- Validates arguments
- Reads input bytes or literal text
- Builds the analyzer configuration
- Loads the selected tradecraft rule set
- Runs recursive analysis
- Writes reports and stage artifacts
- Returns explicit error codes when processing fails

## Data Models

`models.py` defines:

- `TransformCandidate`
- `Stage`
- `Indicator`
- `TradecraftFinding`
- `AnalysisResult`

A `Stage` represents one observed or reconstructed form of the input.

Each stage records:

- Stage ID
- Parent stage ID
- Recursion depth
- Transformation name
- Transformation confidence
- Supporting evidence
- Input and output SHA-256 hashes
- Input and output sizes
- Text preview
- Detected encoding
- Printable-character ratio
- Warnings

`AnalysisResult.stage_bytes` retains the exact byte content of every recorded stage. These bytes are excluded from JSON serialization and exported separately as `.bin` files.

`AnalysisResult.provenance` records the tool version, Python version, UTC generation time, static-analysis mode, active resource limits, and unique-stage lineage policy.

## Transformation Detection

`detectors.py` coordinates text-oriented and binary-oriented transformation detection.

Text-oriented transformations are attempted only when the stage meets the configured printable-character threshold.

Binary signature detection remains available for low-printability content so that a decoded gzip, zlib, Bzip2, or XZ stream can continue through the pipeline.

Whole-stage Base64 and hexadecimal detection is intentionally conservative. The complete normalized stage must match the expected alphabet before decoding is attempted. Decoded content must also be plausible text or begin with a recognized compressed-data signature. Explicit URL-safe Base64 containing `-` or `_` may preserve validated binary output.

## Safe Transformations

`transforms.py` implements decoding and decompression without executing reconstructed content.

Supported operations include:

- Standard Base64
- URL-safe Base64
- PowerShell EncodedCommand
- Hexadecimal
- URL percent encoding
- HTML entities
- Quoted-string concatenation
- Gzip
- Zlib
- Bzip2
- XZ

Simple quoted-string concatenation uses `ast.literal_eval` only for isolated string literals. It does not evaluate variables, function calls, or arbitrary expressions.

Resource controls include maximum input size, recursion depth, stage count, per-stage decoded output, cumulative decoded output, XZ memory use, and transformation preallocation checks. Compressed decoders reconstruct the first supported stream and report remaining members or appended bytes as trailing data.

## Recursive Analysis

`pipeline.py` uses a queue to process stages.

For each accepted transformation candidate, the pipeline:

1. Enforces the output-size limit.
2. Calculates the output SHA-256 hash.
3. Rejects duplicate content hashes.
4. Creates a child stage.
5. Records the exact raw bytes.
6. Adds the child stage to the processing queue.

The configured maximum depth limits recursive processing.

Duplicate-hash suppression prevents redundant work and transformation loops. The recorded lineage contains one stage for each unique output SHA-256 value. When a later transformation produces identical bytes, the duplicate is suppressed and a warning identifies the attempted transform, parent stage, duplicate hash, and existing stage ID.

## Indicator Extraction

`indicators.py` extracts observables only from content recorded in analysis stages.

Current indicator types include:

- URLs
- Domains
- IPv4 addresses
- Email addresses
- Windows registry paths
- Windows file paths
- Selected command interpreters and utilities

Each indicator records the stage where it was observed.

## Tradecraft Rule Engine

`tradecraft.py` loads and validates external JSON rule files.

Current matching methods are:

- Transformation-name matching
- Exact normalized indicator-value matching

Every rule must contain:

- Rule ID
- Title
- Description
- Severity
- Confidence
- Confidence basis
- Match criteria

ATT&CK identifiers and names are optional.

The rule engine records supporting evidence and matching stage IDs. It does not dynamically increase confidence based on the number of matches.

## Confidence

Transformation confidence and tradecraft-finding confidence have different meanings.

Transformation confidence describes the specificity of a detected decoding or decompression operation.

Tradecraft-finding confidence describes how strongly an observed artifact supports a behavioral hypothesis.

Neither score represents the probability that the input is malicious.

See `CONFIDENCE_MODEL.md` for the complete confidence model.

## Reporting

`reporters.py` produces:

- `analysis.json`
- `summary.txt`
- `report.html`
- Exact `.bin` stage artifacts
- Execution provenance
- Active resource-limit metadata
- Readable `.txt` stage previews

All analyzed text is escaped before HTML rendering.

Each HTML stage section links to its raw-byte artifact and text preview.

## Error Handling

- Missing input files return exit code 2.
- Input-read and report-write failures return exit code 3.
- A nonempty output directory is treated as a report-write failure and is not silently overwritten.
- Invalid tradecraft rules return exit code 4.
- Resource-limit failures return exit code 5.
- Successful analysis returns exit code 0.

Malformed or excessive compressed content produces visible warnings rather than being executed or silently ignored.

## Dependency Decision

Version 1.0.0 uses only the Python standard library.

Python 3.10 through 3.13 are the documented and CI-validated support range. Successful execution on another Python version does not expand the officially supported range.

## Deliberately Unsupported Behavior

Tradecraft Unwrapper intentionally does not:

- Execute reconstructed content
- Invoke command interpreters
- Contact URLs
- Resolve domains
- Download files
- Emulate operating-system behavior
- Evaluate arbitrary expressions
- Decrypt unknown encryption
- Claim that ATT&CK hypotheses prove malicious activity
