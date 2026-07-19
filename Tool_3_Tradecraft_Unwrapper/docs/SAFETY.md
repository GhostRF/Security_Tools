# Safety Model

Tradecraft Unwrapper is designed for static analysis of scripts, commands, and encoded content.

## Non-Execution Guarantee

The tool treats all reconstructed content as data.

It does not intentionally use:

- `eval`
- `exec`
- `subprocess`
- `os.system`
- Shell invocation
- PowerShell invocation
- JavaScript execution
- Network clients

Decoded commands are displayed and reported but are not executed.

## Network Isolation

The tool does not:

- Resolve domains
- Contact URLs
- Download payloads
- Query reputation services
- Upload samples
- Submit data to external analysis systems

URLs, domains, and addresses are extracted as text indicators only.

## Resource Controls

The tool provides:

- Maximum input size
- Maximum recursive depth
- Maximum recorded stage count
- Maximum decoded bytes per stage
- Maximum cumulative decoded bytes
- XZ decompression memory limit
- Transformation preallocation checks
- Printable-character threshold
- Duplicate-hash suppression with visible warnings
- Bounded decompression

These controls reduce the risks of uncontrolled recursion, duplicate processing, excessive memory allocation, and decompression expansion.

Compressed decoders reconstruct only the first gzip, zlib, Bzip2, or XZ stream. Remaining members or appended bytes are reported as trailing data and are not silently processed.

They do not make the tool a hardened malware sandbox.

## Output Isolation

The selected output directory must be new or empty. The tool refuses
to mix a new analysis with reports or stage artifacts from an earlier
run. A `.gitkeep` placeholder does not prevent use of an otherwise
empty directory.

This behavior prevents stale files from being mistaken for artifacts
produced by the current analysis.

## HTML Safety

Analyzed content is HTML escaped before being inserted into `report.html`.

An automated regression test verifies that input containing raw `<script>` tags is rendered as escaped text instead of active HTML.

## Raw Artifact Handling

The `.bin` stage artifacts preserve exact reconstructed bytes.

These files may contain malicious, sensitive, or otherwise unsafe content.

Users should:

- Store outputs in an appropriate analysis location
- Avoid executing unknown artifacts
- Avoid double-clicking unknown binary files
- Follow organizational evidence-handling requirements
- Use an isolated analysis environment for genuinely suspicious content
- Delete artifacts when retention is not authorized

## Analytical Limitations

A command name, encoded string, or ATT&CK mapping does not establish malicious intent.

All tradecraft findings are hypotheses requiring analyst review and contextual evidence.

## Authorized Use

Use Tradecraft Unwrapper only with files, commands, systems, and data that you are legally and organizationally authorized to analyze.

## Version 1.1.0 Embedded Fragment Safety

The embedded-fragment scan is opt-in. It is designed to surface analyst-review candidates, not final malicious verdicts.

Safety controls for embedded candidates include strict decoding, printable-output checks, confidence labeling, decoded-size reporting, and evidence text. Analysts should treat the output as triage evidence that requires review.
