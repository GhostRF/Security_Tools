# Design Notes

This document summarizes the design of the ATT&CK-Based Multi-Source Detection Correlator.

## Design Goal

The goal of this tool is to provide a lightweight defensive analysis workflow that can ingest multiple log formats, normalize the records, identify suspicious behavior, map that behavior to MITRE ATT&CK Enterprise techniques, correlate related activity, and produce analyst-friendly outputs.

The tool is intentionally transparent. It uses readable Python logic instead of a black-box model so analysts can understand why an event matched and how an attack chain was created.

## Analysis Pipeline

The tool uses a four-stage pipeline.

## 1. Parse

The parser reads supported input files and directories. Supported formats include:

- JSON
- JSONL
- NDJSON
- CSV
- Zeek `.log` files
- Optional Windows EVTX files when `python-evtx` is installed

When a directory is provided, the tool recursively scans for supported file types.

## 2. Normalize

Each parsed record is converted into a common normalized event structure. This allows the tool to compare records from different sources even when the original field names differ.

The normalizer attempts to extract fields such as:

- Timestamp
- Host
- User
- Source type
- Event ID
- Process name
- Command line
- Parent process
- Source IP
- Destination IP
- Destination port
- DNS query
- Registry key
- File path
- Message text

This normalization step is important because Windows, Sysmon, PowerShell, Zeek, and SIEM exports often represent similar information with different field names.

## 3. Detect and Map

The detection layer uses rule-based logic to identify suspicious patterns in normalized events. Matching events are mapped to MITRE ATT&CK Enterprise technique IDs and tactics.

Examples include:

- Suspicious PowerShell command content mapped to `T1059.001`
- Windows command shell usage mapped to `T1059.003`
- Rundll32 behavior mapped to `T1218.011`
- Regsvr32 behavior mapped to `T1218.010`
- BITS job activity mapped to `T1197`
- NTDS-related credential access mapped to `T1003.003`
- LSASS and Security Account Manager indicators mapped to `T1003`
- Discovery commands mapped to `T1087`, `T1082`, or `T1016`
- Registry run key persistence mapped to `T1547.001`
- Scheduled task activity mapped to `T1053.005`
- Suspicious DNS or network behavior mapped to `T1568.002`, `T1071.001`, or `T1041`

These mappings are not official MITRE detections and are not Sigma rules. They are transparent rule-based mappings for analyst triage and educational use.

## 4. Correlate and Score

Suspicious events are grouped into chains using host, user, and time-window logic. The purpose of correlation is to help analysts identify groups of related activity rather than reviewing each event in isolation.

Risk scoring considers:

- Matched rule severity
- Number of unique ATT&CK techniques
- Number of ATT&CK tactics
- Number of telemetry sources
- Event timing within the correlation window

Scores are capped at 100 and should be treated as triage indicators, not validated incident severity ratings.

## Output Design

The tool writes several outputs to support different analyst workflows:

- `normalized_events.json` for full normalized event review
- `attack_chains.json` for correlated suspicious activity
- `timeline.csv` for spreadsheet-friendly analysis
- `attack_graph.dot` for graph rendering with Graphviz
- `report.html` for human-readable review
- `validation_notes.txt` for caveats and interpretation guidance

## Mordor Dataset Parsing Update

The tool was tested against the OTRF Mordor dataset `empire_ninjacopy_dumping_ntds_dit_file.json`.

Initial result before the parser update:

- Loaded events: 13,969
- Suspicious events: 0
- Attack chains: 0

Issue identified:

- The dataset stores important detection context in the Windows `Message` field instead of only in structured fields such as `CommandLine`, `Image`, or `TargetFilename`.

Update made:

- Added normalized `message` support.
- Added support for Mordor fields including `Hostname`, `SourceName`, `Channel`, `TimeCreated`, and `Message`.
- Added message-based ATT&CK mappings for NinjaCopy, NTDS, PowerShell, LSASS, and Security Account Manager indicators.

Result after the update:

- Loaded events: 13,969
- Suspicious events: 3
- Attack chains: 1
- Top chain risk score: 100
- Host: DC01.pandalab.com

Techniques supported by this update:

- `T1059.001` Command and Scripting Interpreter: PowerShell
- `T1003` OS Credential Dumping
- `T1003.003` OS Credential Dumping: NTDS

## Design Tradeoffs

The tool favors readability and transparency over full detection coverage. This makes it easier to understand, test, and modify, but it also means the rule set is intentionally limited.

The tool does not attempt to replace:

- A SIEM
- An EDR
- A SOAR platform
- Sigma
- YARA
- Full ATT&CK STIX ingestion
- Human analyst review

## Known Limitations

- False positives and false negatives are expected.
- Some detections require useful command-line or message fields.
- Different logging tools may export the same event using different field names.
- Zeek-only data may lack host and user context.
- Risk scoring is not a validated severity model.
- EVTX parsing requires an optional dependency.
- The tool does not provide real-time monitoring.
- The tool does not perform automated response actions.

## Future Improvements

Potential future improvements include:

- External YAML rule loading
- Sigma rule support
- ATT&CK STIX ingestion
- Unit tests for parsers and rules
- More robust Windows message parsing
- Additional public dataset schemas
- Confidence scoring for detections
- Neo4j or graph database export
- Interactive dashboard reporting

## Smoke Test Result After Refinement

After adding parallel file parsing and watch mode, the sample smoke test was rerun.

Command:

~~~bash
python3 attack_correlator.py samples/sample_sysmon.jsonl samples/sample_zeek_dns.jsonl samples/sample_zeek_conn.csv --workers 2
~~~

Result:

~~~text
Loaded events: 6
Suspicious events: 6
Attack chains: 2
~~~

This result is expected because all six synthetic sample events intentionally represent suspicious behaviors used to validate different rule mappings.
