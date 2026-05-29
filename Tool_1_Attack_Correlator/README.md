# ATT&CK-Based Multi-Source Detection Correlator

A lightweight defensive security analysis tool for parsing multiple telemetry sources, normalizing events into a common schema, mapping suspicious activity to MITRE ATT&CK Enterprise techniques, correlating related events by host, user, and time window, and producing analyst-friendly investigation outputs.

This tool was developed as part of a CSC-842 Security Tool Development project, but it is written and documented as a general-purpose open-source security analytics prototype.

## Overview

Security investigations often require analysts to pivot across endpoint, network, DNS, PowerShell, Windows Security, and Sysmon telemetry. Those sources usually use different field names, formats, and levels of detail, which can make it difficult to quickly identify related suspicious activity.

The ATT&CK-Based Multi-Source Detection Correlator provides a transparent Python workflow for:

1. Loading supported log formats.
2. Normalizing source-specific fields.
3. Applying rule-based ATT&CK mappings.
4. Correlating suspicious activity into probable event chains.
5. Producing timeline, graph, JSON, and HTML outputs for analyst review.

The tool is intended for defensive analysis, security education, detection engineering practice, and reproducible experimentation with public security datasets.

## Important Accuracy Statement

The ATT&CK mappings in this project are rule-based and intentionally limited. The tool uses transparent Python rules and pattern matching to associate suspicious log activity with MITRE ATT&CK Enterprise technique IDs.

These mappings are not official MITRE detections, not Sigma rules, and not operationally validated detections.

A match should be interpreted as an analyst lead, not proof of compromise. For example, a PowerShell event containing suspicious command content may be mapped to `T1059.001`, and an event referencing NTDS-related activity may be mapped to `T1003.003`. Those mappings help organize an investigation, but they still require human review, environmental context, and validation.

## Key Features

- Parses JSON, JSONL, NDJSON, CSV, Zeek `.log`, and optional Windows EVTX files.
- Supports endpoint, network, DNS, PowerShell, Windows Security, Sysmon, and Zeek-style telemetry.
- Normalizes source-specific records into a shared event model.
- Handles nested JSON fields such as `process.command_line`.
- Handles newline-delimited JSON files, including datasets that use `.json` extensions for JSONL-style records.
- Applies transparent rule-based mappings to MITRE ATT&CK Enterprise techniques.
- Correlates detections by host, user, and configurable time window.
- Scores correlated event chains for analyst triage.
- Exports normalized events, attack chains, timelines, Graphviz DOT files, HTML reports, and validation notes.
- Includes small synthetic sample logs for smoke testing.
- Supports public dataset testing with OTRF Security-Datasets / Mordor, Splunk BOTS exports, and Malware-Traffic-Analysis.net PCAPs converted to Zeek logs.

## Repository Layout

~~~text
Tool_1_Attack_Correlator/
├── attack_correlator.py          # Main tool
├── requirements.txt              # Python dependencies
├── README.md                     # Project documentation
├── DATASET_INSTRUCTIONS.md       # Public dataset setup guidance
├── samples/                      # Synthetic sample logs for smoke testing
├── docs/                         # Design notes and AI-use documentation
├── data/                         # Local-only dataset location
└── output/                       # Optional local output location
~~~

Large datasets, generated outputs, virtual environments, ZIP files, PCAPs, EVTX files, and local artifacts should not be committed to the repository.

## Supported Inputs

The tool currently supports:

| Input Type | Examples |
|---|---|
| JSON | Windows, Sysmon, Elastic-style, or custom JSON exports |
| JSONL / NDJSON | One JSON object per line |
| CSV | SIEM, Splunk, Zeek, or custom CSV exports |
| Zeek `.log` | `conn.log`, `dns.log`, `http.log`, and similar TSV logs |
| EVTX | Windows Event Log files when `python-evtx` is installed |

The normalizer attempts to extract common fields such as:

~~~text
TimeCreated, @timestamp, UtcTime, ts
Hostname, Computer, host
User, TargetUserName, SubjectUserName
Image, ProcessName, CommandLine
SourceIp, DestinationIp, DestinationPort
QueryName, query
TargetObject, TargetFilename
Message
~~~

## Installation

Clone the repository:

~~~bash
git clone https://github.com/GhostRF/Security_Tools.git
cd Security_Tools/Tool_1_Attack_Correlator

# Optional SSH clone method for users who already have GitHub SSH configured:
git clone git@github.com:GhostRF/Security_Tools.git
~~~

Create and activate a Python virtual environment:

~~~bash
python3 -m venv venv
source venv/bin/activate
~~~

Install dependencies:

~~~bash
pip install -r requirements.txt
~~~

Verify the command-line help:

~~~bash
python attack_correlator.py -h
~~~

## Quick Start

Run the tool against the included synthetic sample files:

~~~bash
python attack_correlator.py samples/sample_sysmon.jsonl samples/sample_zeek_dns.jsonl samples/sample_zeek_conn.csv
~~~

Expected output:

~~~text
Loaded events: 6
Suspicious events: 3
Attack chains: 2
~~~

The tool writes output to:

~~~text
attack_correlator_output/
~~~

Open the HTML report on macOS:

~~~bash
open attack_correlator_output/report.html
~~~

On Linux, use:

~~~bash
xdg-open attack_correlator_output/report.html
~~~

The included sample files are synthetic and are only intended to verify that the tool runs correctly. They should not be described as real incident data.

## Command-Line Usage

~~~bash
python attack_correlator.py [options] inputs [inputs ...]
~~~

Arguments:

| Argument | Description |
|---|---|
| `inputs` | One or more files or directories containing supported log formats |

Options:

| Option | Description |
|---|---|
| `-h`, `--help` | Show command-line help |
| `-o`, `--output` | Output directory. Default is `attack_correlator_output` |
| `-w`, `--window` | Correlation window in minutes |
| `--min-risk` | Minimum risk threshold for reported chains |

Example:

~~~bash
python attack_correlator.py /path/to/logs -o investigation_output --window 90 --min-risk 25
~~~

When a directory is provided, the tool recursively scans supported files.

## Output Files

The tool generates several output files for analyst review:

| File | Description |
|---|---|
| `normalized_events.json` | All parsed and normalized events |
| `attack_chains.json` | Correlated suspicious event chains with techniques, tactics, and risk scores |
| `timeline.csv` | Suspicious event timeline for review and reporting |
| `attack_graph.dot` | Graphviz DOT representation of correlated event chains |
| `report.html` | Human-readable HTML report |
| `validation_notes.txt` | Notes about limitations and interpretation |

Optional graph rendering with Graphviz:

~~~bash
dot -Tpng attack_correlator_output/attack_graph.dot -o attack_correlator_output/attack_graph.png
~~~

## Public Dataset Testing

The repository does not include large public datasets. Users should download public datasets from their original sources and store them locally.

Recommended local-only dataset directories:

~~~text
data/mordor/
data/bots/
data/mta_case/
~~~

Example using the OTRF Mordor dataset `empire_ninjacopy_dumping_ntds_dit_file.json`:

~~~bash
python attack_correlator.py data/mordor/empire_ninjacopy_dumping_ntds_dit_file.json
~~~

Validated local test result after the Mordor parser update:

~~~text
Loaded events: 13969
Suspicious events: 3
Attack chains: 1
Top chain: Risk 100 | Host DC01.pandalab.com | User unknown | Events 3
~~~

See `DATASET_INSTRUCTIONS.md` for additional dataset setup guidance.

## Design Summary

The tool uses a four-stage analysis pipeline.

### 1. Parse

The parser reads supported files, including JSON, JSONL, NDJSON, CSV, Zeek TSV logs, and optional Windows EVTX files.

### 2. Normalize

Source-specific records are converted into a common event model. This helps compare and correlate activity across different telemetry sources.

### 3. Detect and Map

Rule-based detection logic inspects normalized fields such as process name, command line, DNS query, destination port, registry key, file path, and message text. Matching events are mapped to MITRE ATT&CK Enterprise technique IDs, tactics, severity values, and risk weights.

### 4. Correlate and Score

Detections are grouped by host, user, and time window. Chains are ordered using ATT&CK tactic progression and scored using severity, technique diversity, tactic diversity, source diversity, and activity timing.

## Risk Scoring

Risk scores are intended for triage, not as validated incident severity ratings.

The score considers:

- Severity of matched detections
- Number of unique ATT&CK techniques
- Number of ATT&CK tactics represented
- Number of telemetry sources involved
- Activity occurring within a compressed time window

Scores are capped at 100.

## Built-In ATT&CK Mappings

Current built-in rule mappings include:

| Technique ID | Technique |
|---|---|
| `T1059.001` | Command and Scripting Interpreter: PowerShell |
| `T1059.003` | Command and Scripting Interpreter: Windows Command Shell |
| `T1105` | Ingress Tool Transfer |
| `T1197` | BITS Jobs |
| `T1218.011` | Rundll32 |
| `T1218.010` | Regsvr32 |
| `T1003` | OS Credential Dumping |
| `T1003.003` | OS Credential Dumping: NTDS |
| `T1087` | Account Discovery |
| `T1082` | System Information Discovery |
| `T1016` | System Network Configuration Discovery |
| `T1547.001` | Registry Run Keys / Startup Folder |
| `T1053.005` | Scheduled Task |
| `T1071.001` | Application Layer Protocol: Web Protocols |
| `T1568.002` | Domain Generation Algorithms |
| `T1560` | Archive Collected Data |
| `T1041` | Exfiltration Over C2 Channel |
| `T1204.002` | User Execution: Malicious File |

## Mordor Dataset Parser Update

During testing with the OTRF Mordor dataset `empire_ninjacopy_dumping_ntds_dit_file.json`, the initial version of the tool loaded the dataset but produced no suspicious detections.

Initial result:

~~~text
Loaded events: 13969
Suspicious events: 0
Attack chains: 0
~~~

Root cause:

~~~text
Important Windows event details were stored in the Message field rather than only in structured fields such as CommandLine, Image, TargetFilename, or QueryName.
~~~

Update made:

- Added normalized `message` support.
- Added support for Mordor fields including `Hostname`, `SourceName`, `Channel`, `TimeCreated`, and `Message`.
- Added message-based ATT&CK mappings for NinjaCopy, NTDS, PowerShell, LSASS, and Security Account Manager indicators.

Updated result:

~~~text
Loaded events: 13969
Suspicious events: 3
Attack chains: 1
Top chain: Risk 100 | Host DC01.pandalab.com | User unknown | Events 3
~~~

This update demonstrates how parser coverage directly affects detection quality.

## Known Limitations

- Built-in rules are rule-based and intentionally limited.
- The tool does not ingest the full MITRE ATT&CK STIX corpus.
- The tool does not execute Sigma rules.
- The tool does not replace SIEM, EDR, SOAR, Sigma, YARA, or human analysis.
- Risk scoring is not a validated severity model.
- EVTX parsing depends on the optional `python-evtx` package.
- Windows event field names vary by collector and export method.
- Zeek-only datasets may lack host and user context.
- Some detections require structured fields or useful message text to be present.
- False positives and false negatives are expected.

## Suggested Future Enhancements

Potential future improvements include:

- YAML-based external rule loading
- Sigma rule support
- MITRE ATT&CK STIX ingestion
- Unit tests for parsers and detection rules
- Confidence scoring per detection
- Neo4j export
- Interactive web dashboard
- Additional EVTX parser coverage
- Additional public dataset schema support
- More robust field extraction from Windows event messages

## AI Use Disclosure

AI assistance was used during development planning, documentation drafting, troubleshooting, and refinement of parser and detection logic.

Human review and validation were performed through:

- Python syntax checking with `python -m py_compile`
- Synthetic sample testing
- Public Mordor dataset testing
- Manual review of output files and detection results
- Review of ATT&CK technique IDs and names for consistency

AI-generated suggestions were modified, tested, and validated before inclusion.

## Responsible Use

This tool is intended for defensive analysis, education, and security research. It does not perform exploitation, payload generation, credential theft, persistence, command-and-control, or other offensive actions.

Use it only with logs, datasets, and systems that you are authorized to analyze.

## License

No license has been selected yet. Until a license is added, standard copyright restrictions apply.
