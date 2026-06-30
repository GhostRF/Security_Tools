# Testing Guide

## Environment

Minimum supported version:

~~~text
Python 3.10
~~~

No third-party Python packages are required.

## Compilation Check

From the Tool 3 directory:

~~~bash
python3 -m py_compile \
  tradecraft_unwrapper.py \
  tradecraft_unwrapper_core/*.py \
  tests/*.py
~~~

No output indicates successful compilation.

## Automated Tests

Run:

~~~bash
python3 -m unittest discover -s tests -v
~~~

Current expected result:

~~~text
Ran 37 tests
OK
~~~

## Test Coverage

The test suite verifies:

- Standard Base64
- URL-safe Base64
- PowerShell EncodedCommand
- Hexadecimal decoding
- URL percent decoding
- HTML entities
- Quoted-string concatenation
- Gzip
- Zlib
- Bzip2
- XZ/LZMA
- Recursive processing
- Maximum recursion depth
- Maximum decoded output
- Malformed compressed input
- Benign plaintext handling
- External tradecraft rules
- Rule-schema validation
- Confidence-basis requirements
- ATT&CK hypotheses
- JSON reporting
- Text reporting
- HTML reporting
- HTML escaping
- Exact raw-byte preservation
- Transformation-confidence labeling
- Command-line execution

## Reproducible Sample Tests

### Benign plaintext

~~~bash
python3 tradecraft_unwrapper.py \
  samples/benign_plaintext.txt \
  -o output/benign
~~~

Expected:

- One stage
- Zero decoded stages
- No transformation finding

### Nested Base64 and URL encoding

~~~bash
python3 tradecraft_unwrapper.py \
  samples/nested_multistage.txt \
  -o output/nested
~~~

Expected:

- Three stages
- Two decoded stages
- Base64 followed by URL-percent decoding

### Base64 followed by gzip

~~~bash
python3 tradecraft_unwrapper.py \
  samples/compressed_base64.txt \
  -o output/compressed
~~~

Expected:

- Three stages
- Base64 followed by gzip
- Final decoded text containing the safe training command

### Tradecraft findings

~~~bash
python3 tradecraft_unwrapper.py \
  samples/tradecraft_findings.txt \
  -o output/tradecraft
~~~

Expected totals:

~~~text
Stages observed: 2
Decoded stages: 1
Indicators extracted: 2
Tradecraft findings: 3
~~~

Expected ATT&CK hypotheses:

- T1027
- T1059.001
- T1059.003

## JSON Validation

~~~bash
python3 -m json.tool \
  output/tradecraft/analysis.json \
  > /dev/null

echo "JSON validation exit code: $?"
~~~

Expected:

~~~text
JSON validation exit code: 0
~~~

## Raw Artifact Verification

Each exported `.bin` file should hash to the corresponding `output_sha256` value in `analysis.json`.

## Manual HTML Review

Open the report on macOS:

~~~bash
open output/tradecraft/report.html
~~~

Verify:

- Summary totals
- Transformation stages
- Transform-confidence labels
- Indicator table
- Finding severity
- Finding confidence
- Confidence basis
- ATT&CK hypothesis
- Raw-byte links
- Text-preview links
