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

- Maximum recursive depth
- Maximum decoded bytes per stage
- Printable-character threshold
- Duplicate-hash suppression
- Bounded decompression

These controls reduce the risks of uncontrolled recursion, duplicate processing, and excessive decompression expansion.

They do not make the tool a hardened malware sandbox.

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
