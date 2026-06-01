# Dataset Instructions

This document explains how to obtain and prepare public datasets for testing the ATT&CK-Based Multi-Source Detection Correlator.

The repository includes small synthetic sample files in the `samples/` directory for smoke testing. Larger public datasets are not included in this repository because of size, licensing, and safety considerations. Users should download public datasets directly from their original sources and run the tool locally.

## Supported Input Types

The tool currently supports:

- JSON
- JSONL / newline-delimited JSON
- NDJSON
- CSV
- Zeek `.log` files
- Windows EVTX files, when the optional `python-evtx` dependency is installed

The parser normalizes common Windows, Sysmon, PowerShell, Security, Zeek, DNS, and network fields into a shared event model before applying rule-based ATT&CK mappings.

## Quick Smoke Test

Use the included synthetic sample files to confirm the tool runs correctly:

~~~bash
python attack_correlator.py samples/sample_sysmon.jsonl samples/sample_zeek_dns.jsonl samples/sample_zeek_conn.csv
~~~

Expected behavior:

~~~text
Loaded events: 6
Suspicious events: 6
Attack chains: 2
~~~

The tool should generate output files in:

~~~text
attack_correlator_output/
~~~

The synthetic samples are for functionality testing only. They are not from a real incident.

## Dataset Option 1: OTRF Security-Datasets / Mordor

OTRF Security-Datasets provides public, pre-recorded security telemetry that can be used for detection engineering, analytics development, and ATT&CK-aligned research.

A useful test dataset for this tool is:

~~~text
empire_ninjacopy_dumping_ntds_dit_file.json
~~~

This dataset is useful for testing message-field parsing and ATT&CK mappings related to PowerShell, NinjaCopy, LSASS, Security Account Manager access, and NTDS-related credential access.

Suggested local directory:

~~~bash
mkdir -p data/mordor
~~~

Download the selected dataset from the OTRF Security-Datasets repository and place it in:

~~~text
data/mordor/
~~~

Run the tool:

~~~bash
python attack_correlator.py data/mordor/empire_ninjacopy_dumping_ntds_dit_file.json
~~~

Expected behavior with the current parser and detection rules:

~~~text
Loaded events: 13969
Suspicious events: 3
Attack chains: 1
~~~

The exact count may change if detection rules are modified.

Important note: Some Mordor files use newline-delimited JSON even when the file extension is `.json`. The tool handles this format.

## Dataset Option 2: Splunk BOTS Export

Splunk Boss of the SOC, commonly called BOTS, provides public security datasets for analyst training and detection development.

These datasets are often Splunk-oriented, so users may need to export relevant events to CSV or JSON before using this tool.

Suggested workflow:

1. Download a BOTS dataset.
2. Load the dataset into Splunk or another compatible analysis environment.
3. Export relevant Sysmon, Windows Security, Zeek/Bro connection, DNS, or HTTP records as CSV or JSON.
4. Run the exported files through the correlator.

Example command:

~~~bash
python attack_correlator.py bots_sysmon_export.csv bots_conn_export.csv bots_dns_export.csv -o output_bots
~~~

Best results are expected from exports that include process creation, command line, DNS, network connection, file creation, registry, or authentication fields.

## Dataset Option 3: Malware-Traffic-Analysis.net PCAP Converted to Zeek

Malware-Traffic-Analysis.net provides public malware traffic exercises.

The correlator does not process PCAP files directly, but users can convert PCAPs into Zeek logs and then ingest the resulting `.log` files.

Suggested workflow:

~~~bash
mkdir -p data/mta_case
cd data/mta_case

# Manually download a selected PCAP from Malware-Traffic-Analysis.net.
# Then convert it to Zeek logs:
zeek -r suspicious_case.pcap

cd ../..
python attack_correlator.py data/mta_case/conn.log data/mta_case/dns.log data/mta_case/http.log -o output_mta
~~~

Useful Zeek logs may include:

~~~text
conn.log
dns.log
http.log
ssl.log
files.log
weird.log
~~~

Safety note: Treat PCAPs, extracted payloads, and related artifacts as potentially malicious. Analyze them in an isolated virtual machine or lab environment. Do not execute extracted binaries or scripts.

## Dataset Storage Guidance

Large datasets should not be committed to this repository.

Recommended local-only locations:

~~~text
data/mordor/
data/bots/
data/mta_case/
~~~

The `.gitignore` file should exclude local datasets, generated output, ZIP archives, PCAPs, EVTX files, and virtual environments.

## Output Files

By default, the tool writes results to:

~~~text
attack_correlator_output/
~~~

Typical output files include:

~~~text
normalized_events.json
attack_chains.json
timeline.csv
attack_graph.dot
report.html
validation_notes.txt
~~~

These files are generated locally and should not be committed unless a user intentionally wants to publish a small demonstration result.

## Interpretation Guidance

The ATT&CK mappings are rule-based. A match means the event resembles behavior associated with a technique. It does not prove that an intrusion occurred.


~~~text
The tool provides analyst triage support by correlating events and mapping suspicious patterns to ATT&CK techniques. Results should be reviewed by a human analyst before operational conclusions are made.
~~~

## Reproducibility Notes

For reproducible testing:

1. Record the dataset name and source.
2. Record the command used to run the tool.
3. Save the generated `report.html`, `timeline.csv`, and `attack_chains.json` locally.
4. Document any parser or rule changes that affect detection counts.

Detection counts may change as parsing and rule logic are improved.
