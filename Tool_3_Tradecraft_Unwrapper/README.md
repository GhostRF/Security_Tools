# Tradecraft Unwrapper

Tradecraft Unwrapper is a static, non-executing analyzer for encoded, compressed, escaped, and reconstructed scripts and command lines.

The tool recursively identifies supported transformations, preserves the complete transformation lineage, extracts observable indicators, applies evidence-based tradecraft rules, and generates JSON, text, HTML, and forensic stage artifacts.

Tradecraft Unwrapper does not execute analyzed content, invoke a command interpreter, make network connections, or download referenced resources.

## Problem Addressed

Security analysts frequently encounter suspicious scripts and command lines that contain multiple layers of encoding, compression, escaping, or string construction. Many decoding utilities process only one layer or return the final content without documenting how the result was obtained.

Tradecraft Unwrapper preserves an auditable transformation chain:

~~~text
Original input
-> detected transformation
-> reconstructed stage
-> additional transformations
-> extracted indicators
-> evidence-based tradecraft hypotheses
~~~

Every stage records:

- Unique stage ID
- Parent stage ID
- Recursion depth
- Transformation type
- Transformation confidence
- Supporting evidence
- Input and output SHA-256 hashes
- Input and output sizes
- Detected text encoding
- Printable-character ratio
- Warnings
- Exact raw bytes
- Text preview

## Current Version

Stable release: `1.0.0`

Version 1.0.0 completed documentation, automated testing, cross-version CI validation, and release review on June 29, 2026.

## Supported Transformations

Tradecraft Unwrapper currently supports:

- Standard Base64
- URL-safe Base64
- PowerShell `EncodedCommand` using UTF-16LE
- Hexadecimal encoding
- URL percent encoding
- HTML entity encoding
- Simple quoted-string concatenation using plus signs
- Gzip compression
- Zlib compression
- Bzip2 compression
- XZ compression

## Analysis Capabilities

- Recursive multi-stage reconstruction
- Parent and child stage lineage
- SHA-256 hashing for every stage
- Duplicate-stage suppression
- Configurable recursion depth
- Configurable decoded-output size limit
- Configurable printable-character threshold
- Exact raw-byte preservation
- Text-preview generation
- Indicator extraction
- External JSON tradecraft rules
- Confidence scores with mandatory confidence explanations
- Conservative MITRE ATT&CK hypotheses
- JSON, text, and HTML reporting

## Extracted Indicator Types

The current indicator extractor supports:

- URLs
- Domains
- IPv4 addresses
- Email addresses
- Windows registry paths
- Windows file paths
- Selected command interpreters and dual-use utilities

Recognized command indicators currently include:

- `powershell`
- `powershell.exe`
- `pwsh`
- `pwsh.exe`
- `cmd`
- `cmd.exe`
- `wscript`
- `wscript.exe`
- `cscript`
- `cscript.exe`
- `mshta`
- `mshta.exe`
- `rundll32`
- `rundll32.exe`
- `regsvr32`
- `regsvr32.exe`
- `certutil`
- `certutil.exe`
- `curl`
- `curl.exe`
- `wget`
- `wget.exe`

## Safety Properties

Tradecraft Unwrapper:

- Does not execute decoded content
- Does not use `eval` or `exec`
- Does not invoke PowerShell, Bash, cmd.exe, or another shell
- Does not make network connections
- Does not resolve domains
- Does not download referenced content
- Does not modify the analyzed input
- Enforces configurable recursion and output-size limits
- Suppresses duplicate stage hashes
- Escapes analyzed content before placing it in HTML reports

The tool is a static decoding and triage utility. It is not a malware sandbox and does not determine whether an input is malicious.

See [`docs/SAFETY.md`](docs/SAFETY.md) for the complete safety model.

## Requirements

- Python 3.10 through 3.13
- No third-party Python packages

The implementation uses only the Python standard library.

## Installation

Clone the repository:

~~~bash
git clone https://github.com/GhostRF/Security_Tools.git
cd Security_Tools/Tool_3_Tradecraft_Unwrapper
~~~

Verify the Python version:

~~~bash
python3 --version
~~~

Display command help:

~~~bash
python3 tradecraft_unwrapper.py --help
~~~

Display the application version:

~~~bash
python3 tradecraft_unwrapper.py --version
~~~

## Basic Usage

### Analyze a file

~~~bash
python3 tradecraft_unwrapper.py \
  samples/nested_multistage.txt \
  -o output/nested
~~~

### Analyze literal text

~~~bash
python3 tradecraft_unwrapper.py \
  --text 'cmd.exe /c echo training' \
  -o output/literal
~~~

### Analyze a PowerShell EncodedCommand sample

~~~bash
python3 tradecraft_unwrapper.py \
  samples/tradecraft_findings.txt \
  -o output/tradecraft
~~~

### Analyze Base64 followed by gzip

~~~bash
python3 tradecraft_unwrapper.py \
  samples/compressed_base64.txt \
  -o output/compressed
~~~

### Use an external rule file

~~~bash
python3 tradecraft_unwrapper.py \
  samples/tradecraft_findings.txt \
  --rules rules/default.json \
  -o output/custom-rules
~~~

### Change processing limits

~~~bash
python3 tradecraft_unwrapper.py \
  samples/nested_multistage.txt \
  --max-depth 3 \
  --max-bytes 524288 \
  --min-printable-ratio 0.70 \
  -o output/limited
~~~

## Command-Line Options

| Option | Purpose |
|---|---|
| `input` | Path to the file that will be analyzed |
| `--text` | Analyze a literal command or text string instead of a file |
| `-o`, `--output` | Select the output directory |
| `--rules` | Select an external JSON tradecraft rule file |
| `--max-depth` | Set the maximum recursive transformation depth |
| `--max-bytes` | Set the maximum output accepted from one decoded stage |
| `--min-printable-ratio` | Set the printable-character threshold for text-oriented decoders |
| `--version` | Display the application version |
| `--help` | Display command help |

An input file and `--text` cannot be used together.

## Output Files

Each analysis produces the following structure:

~~~text
output-directory/
├── analysis.json
├── summary.txt
├── report.html
└── stages/
    ├── stage_00_input.bin
    ├── stage_00_input.txt
    ├── stage_01_<transform>.bin
    └── stage_01_<transform>.txt
~~~

### `analysis.json`

Contains structured:

- Source metadata
- Ruleset metadata
- Transformation stages
- SHA-256 hashes
- Extracted indicators
- Tradecraft findings
- Confidence explanations
- ATT&CK hypotheses
- Warnings

Exact raw stage bytes are not embedded directly in JSON because byte sequences are not natively JSON serializable.

### `summary.txt`

Provides a human-readable report containing:

- Analysis totals
- Transformation lineage
- Indicators
- Tradecraft findings
- Finding confidence
- Confidence basis
- ATT&CK hypotheses
- Evidence
- Warnings

### `report.html`

Provides a visual report with embedded styling.

The HTML report displays:

- Source information
- Ruleset information
- Stage counts
- Transformation details
- Transform confidence
- Indicators
- Tradecraft findings
- Finding confidence
- Confidence basis
- ATT&CK hypotheses
- Warnings
- Links to raw bytes and text previews

Analyzed content is HTML escaped before rendering.

### Stage `.bin` files

Each `.bin` file contains the exact bytes recorded for that stage.

The SHA-256 hash of each `.bin` file should match the corresponding `output_sha256` value recorded in `analysis.json`.

### Stage `.txt` files

Each `.txt` file contains the text preview used during analysis.

Binary content that is not valid UTF-8 may contain replacement characters in its text preview. The corresponding `.bin` file preserves the exact original bytes.

## Transformation Lineage

Every decoded stage references its parent stage.

For example:

~~~text
Stage 0: input
Stage 1: base64
Stage 2: gzip
~~~

This indicates that:

1. The analyst supplied the original input.
2. The input was decoded as Base64.
3. The Base64 output was recognized and decompressed as gzip.

Each stage also records its depth, size, hash, encoding, confidence, and supporting evidence.

## Confidence Interpretation

Tradecraft Unwrapper uses two different confidence concepts.

### Transformation confidence

Transformation confidence describes how strongly the input structure supports a particular decoding or decompression operation.

For example, a valid gzip signature followed by successful decompression provides strong evidence that the stage is gzip data.

### Tradecraft-finding confidence

Finding confidence describes how strongly the observed evidence supports a behavioral hypothesis.

It does not represent:

- The probability that the input is malicious
- A statistical probability
- A malware verdict
- Proof that an ATT&CK technique was executed
- The severity of the behavior

Every tradecraft rule must include a `confidence_basis` explaining why the score was selected.

The current interpretation is:

| Score | Interpretation |
|---:|---|
| 90–100 | High confidence that a direct and specific observable supports the behavioral hypothesis |
| 75–89 | Moderate confidence based on a direct dual-use artifact whose intent remains ambiguous |
| 50–74 | Contextual confidence based on a broad transformation or indirect observable with common legitimate uses |
| 0–49 | Low-confidence or experimental evidence that default rules should generally avoid |

See [`docs/CONFIDENCE_MODEL.md`](docs/CONFIDENCE_MODEL.md) for the complete confidence model.

## Severity Versus Confidence

Severity and confidence are separate.

- Confidence describes the strength of evidence supporting a hypothesis.
- Severity describes the potential analytical priority of the observed behavior.

A finding can have high confidence but only medium severity. For example, the presence of `powershell.exe` may be directly observable while still representing legitimate administration.

## MITRE ATT&CK Hypotheses

The bundled conservative rule set currently includes hypotheses for:

| ATT&CK ID | Technique |
|---|---|
| T1027 | Obfuscated Files or Information |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| T1218.005 | System Binary Proxy Execution: Mshta |
| T1218.010 | System Binary Proxy Execution: Regsvr32 |
| T1218.011 | System Binary Proxy Execution: Rundll32 |

An ATT&CK mapping means that observed evidence is consistent with the technique description.

It does not prove:

- Adversary activity
- Malicious intent
- Successful execution
- Compromise
- Technique completion

All mappings require analyst review and supporting context.

## External Tradecraft Rules

Tradecraft rules are stored in JSON.

The bundled rule file is:

~~~text
rules/default.json
~~~

A rule includes:

- `rule_id`
- `title`
- `description`
- `severity`
- `confidence`
- `confidence_basis`
- Optional `attack_id`
- Optional `attack_name`
- `match` criteria

The current rule engine supports:

- Transformation-name matches
- Exact normalized indicator-value matches

Rules must use schema version 1 and pass validation before analysis begins.

See [`rules/README.md`](rules/README.md) for rule-format details.

## Sample Files

| File | Purpose |
|---|---|
| `benign_plaintext.txt` | Verifies that ordinary text is not incorrectly decoded |
| `base64_command.txt` | Demonstrates standard Base64 decoding |
| `powershell_encoded_command.txt` | Demonstrates PowerShell EncodedCommand decoding |
| `url_encoded_command.txt` | Demonstrates URL-percent decoding |
| `nested_multistage.txt` | Demonstrates recursive Base64 and URL-percent decoding |
| `compressed_base64.txt` | Demonstrates Base64 followed by gzip decompression |
| `html_entity_command.txt` | Demonstrates HTML entity decoding |
| `concatenated_command.txt` | Demonstrates safe quoted-string reconstruction |
| `malformed_input.txt` | Verifies safe handling of unsupported or malformed content |
| `tradecraft_findings.txt` | Demonstrates indicators and conservative ATT&CK hypotheses |

All included samples are synthetic and harmless.

## Reproducible Demonstration

Run:

~~~bash
rm -rf output/demo

python3 tradecraft_unwrapper.py \
  samples/tradecraft_findings.txt \
  -o output/demo
~~~

Expected command-line totals:

~~~text
Unique stages recorded: 2
Derived stages: 1
Indicators extracted: 2
Tradecraft findings: 3
~~~

Expected indicators:

- `powershell.exe`
- `cmd.exe`

Expected ATT&CK hypotheses:

- T1027
- T1059.001
- T1059.003

Open the HTML report on macOS:

~~~bash
open output/demo/report.html
~~~

Validate the JSON report:

~~~bash
python3 -m json.tool \
  output/demo/analysis.json \
  > /dev/null

echo "JSON validation exit code: $?"
~~~

Expected:

~~~text
JSON validation exit code: 0
~~~

## Testing

Compile the source and tests:

~~~bash
python3 -m py_compile \
  tradecraft_unwrapper.py \
  tradecraft_unwrapper_core/*.py \
  tests/*.py
~~~

No output indicates successful compilation.

Run the complete automated test suite:

~~~bash
python3 -m unittest discover -s tests -v
~~~

The current suite contains 64 tests.

Expected conclusion:

~~~text
Ran 64 tests
OK
~~~

The suite covers:

- Standard Base64
- URL-safe Base64
- PowerShell EncodedCommand
- Hexadecimal decoding
- URL percent decoding
- HTML entity decoding
- Quoted-string concatenation
- Gzip
- Zlib
- Bzip2
- XZ
- Recursive processing
- Maximum recursion depth
- Maximum decoded output
- Malformed input handling
- External rule validation
- Confidence-basis requirements
- ATT&CK hypotheses
- Report generation
- HTML escaping
- Exact raw-byte preservation
- Command-line execution

See [`docs/TESTING.md`](docs/TESTING.md) for the complete testing procedure.

## Project Structure

~~~text
Tool_3_Tradecraft_Unwrapper/
├── tradecraft_unwrapper.py
├── tradecraft_unwrapper_core/
│   ├── __init__.py
│   ├── cli.py
│   ├── detectors.py
│   ├── indicators.py
│   ├── models.py
│   ├── pipeline.py
│   ├── reporters.py
│   ├── tradecraft.py
│   └── transforms.py
├── rules/
│   ├── default.json
│   └── README.md
├── samples/
├── tests/
├── docs/
├── output/
├── README.md
├── CHANGELOG.md
├── requirements.txt
└── .gitignore
~~~

## Architecture Summary

- `tradecraft_unwrapper.py` provides the application entry point.
- `cli.py` handles argument parsing and user-facing execution.
- `detectors.py` coordinates transformation detection.
- `transforms.py` performs safe decoding and decompression.
- `pipeline.py` manages recursive stage processing.
- `models.py` defines analysis data structures.
- `indicators.py` extracts observable artifacts.
- `tradecraft.py` loads, validates, and evaluates external rules.
- `reporters.py` generates reports and forensic artifacts.

See [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) for the full architecture description.

## Error Handling and Exit Codes

| Exit code | Meaning |
|---:|---|
| 0 | Analysis completed successfully |
| 2 | Invalid command-line arguments or missing input file |
| 3 | Input-read or report-write failure |
| 4 | Invalid or unreadable tradecraft rule file |

Malformed transformations may produce warnings without terminating the entire analysis.

## Known Limitations

- The tool performs static analysis only.
- It does not execute or emulate commands.
- It does not determine malicious intent.
- Detection is limited to implemented transformations.
- String reconstruction supports only quoted literals joined by plus signs.
- Indicator extraction uses regular expressions and may produce false positives or omit unusual formats.
- The current rule engine supports exact normalized indicator values and transformation names.
- ATT&CK findings are hypotheses requiring analyst review.
- Password-protected archives are not supported.
- Encrypted payloads are not automatically decrypted.
- Arbitrary JavaScript, PowerShell, shell, or Python expression evaluation is intentionally unsupported.
- The tool does not perform sandboxing, behavioral monitoring, or dynamic analysis.
- Resource limits reduce risk but do not make the tool a hardened malware sandbox.

## Documentation

Additional documentation includes:

- [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md)
- [`docs/SAFETY.md`](docs/SAFETY.md)
- [`docs/TESTING.md`](docs/TESTING.md)
- [`docs/CONFIDENCE_MODEL.md`](docs/CONFIDENCE_MODEL.md)
- [`docs/AI_USAGE.md`](docs/AI_USAGE.md)
- [`rules/README.md`](rules/README.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## AI Usage

ChatGPT was used as a development assistant for brainstorming, architecture, code drafting, testing, debugging, safety review, and documentation.

AI-generated suggestions were reviewed, tested, corrected, or rejected as necessary. The project includes documented examples of defects identified through testing and manual review.

See [`docs/AI_USAGE.md`](docs/AI_USAGE.md) for the full disclosure.

## Authorized Use

Use this tool only with files, commands, systems, and data that you are authorized to analyze.

Raw stage artifacts may contain sensitive, harmful, or malicious content. Handle them according to appropriate forensic, legal, organizational, and evidence-retention procedures.

Do not execute unknown `.bin` artifacts generated by the tool.

## Repository

https://github.com/GhostRF/Security_Tools/tree/main/Tool_3_Tradecraft_Unwrapper
