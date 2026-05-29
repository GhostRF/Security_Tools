#!/usr/bin/env python3
"""
ATT&CK-Based Multi-Source Detection Correlator
CSC-842 Security Tool Development

Purpose:
    Ingest Windows/Sysmon-style JSON or CSV logs, Zeek JSON/CSV logs, and optional
    Windows EVTX files, normalize them, map events to MITRE ATT&CK techniques,
    correlate activity by host/user/time window, and generate timelines, probable
    attack chains, risk scores, and graph exports.

Notes:
    - This tool is defensive and analytic. It does not execute offensive actions.
    - EVTX support requires the optional python-evtx package.
    - Built-in ATT&CK mappings are intentionally transparent and editable.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET

try:
    from Evtx.Evtx import Evtx  # type: ignore
except Exception:  # pragma: no cover
    Evtx = None

ISO_CANDIDATES = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]

SEVERITY_WEIGHTS = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 70,
}

# Transparent, editable mappings. These are not a full ATT&CK corpus.
# They are heuristic mappings designed for a class tool and should be validated
# before operational use. Technique IDs/names below were checked against MITRE
# ATT&CK Enterprise pages during tool preparation; the behavioral logic remains
# heuristic, not authoritative.
DETECTION_RULES = [
    {
        "name": "PowerShell suspicious command line",
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "severity": "high",
        "event_match": {"event_category": ["process"], "process_name": ["powershell.exe", "pwsh.exe"]},
        "regex_fields": {"command_line": r"(?i)(-enc|-encodedcommand|iex|invoke-expression|downloadstring|frombase64string|bypass|nop|hidden)"},
    },
    {
        "name": "Windows command shell suspicious command line",
        "technique_id": "T1059.003",
        "technique": "Windows Command Shell",
        "tactic": "Execution",
        "severity": "medium",
        "event_match": {"event_category": ["process"], "process_name": ["cmd.exe"]},
        "regex_fields": {"command_line": r"(?i)(/c\s+whoami|net\s+user|net\s+localgroup|reg\s+save|vssadmin|wmic|certutil)"},
    },
    {
        "name": "Certutil download or encode behavior",
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "high",
        "event_match": {"event_category": ["process"], "process_name": ["certutil.exe"]},
        "regex_fields": {"command_line": r"(?i)(-urlcache|-split|-f|http|https|ftp|-decode|-encode)"},
    },
    {
        "name": "Bitsadmin transfer behavior",
        "technique_id": "T1197",
        "technique": "BITS Jobs",
        "tactic": "Defense Evasion/Persistence",
        "severity": "high",
        "event_match": {"event_category": ["process"], "process_name": ["bitsadmin.exe"]},
        "regex_fields": {"command_line": r"(?i)(/transfer|/create|/addfile|http|https)"},
    },
    {
        "name": "Rundll32 suspicious execution",
        "technique_id": "T1218.011",
        "technique": "Rundll32",
        "tactic": "Defense Evasion",
        "severity": "medium",
        "event_match": {"event_category": ["process"], "process_name": ["rundll32.exe"]},
        "regex_fields": {"command_line": r"(?i)(javascript:|url\.dll|shell32\.dll|http|https|,StartW|Control_RunDLL)"},
    },
    {
        "name": "Regsvr32 suspicious execution",
        "technique_id": "T1218.010",
        "technique": "Regsvr32",
        "tactic": "Defense Evasion",
        "severity": "high",
        "event_match": {"event_category": ["process"], "process_name": ["regsvr32.exe"]},
        "regex_fields": {"command_line": r"(?i)(/s|/u|/i:|scrobj\.dll|http|https)"},
    },
    {
        "name": "Credential dumping indicator",
        "technique_id": "T1003",
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "severity": "critical",
        "event_match": {"event_category": ["process"]},
        "regex_fields": {"command_line": r"(?i)(lsass|procdump|comsvcs\.dll|sekurlsa|mimikatz|nanodump|taskmgr.*dump)"},
    },
    {
        "name": "Message-based PowerShell NinjaCopy or NTDS activity",
        "technique_id": "T1059.001",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "severity": "high",
        "event_match": {"event_category": ["generic", "process"]},
        "regex_fields": {
            "message": r"(?i)(invoke-ninjacopy|ninjacopy|ntds\.dit|encodedcommand|frombase64string)"
        },
    },
    {
        "name": "Message-based NTDS credential access indicator",
        "technique_id": "T1003.003",
        "technique": "OS Credential Dumping: NTDS",
        "tactic": "Credential Access",
        "severity": "critical",
        "event_match": {"event_category": ["generic", "process", "file"]},
        "regex_fields": {
            "message": r"(?i)(ntds\.dit|invoke-ninjacopy|ninjacopy)"
        },
    },
    {
        "name": "Message-based LSASS access to Security Account Manager objects",
        "technique_id": "T1003",
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "severity": "medium",
        "event_match": {"event_category": ["generic"]},
        "regex_fields": {
            "message": r"(?is)(security account manager.*lsass\.exe.*(readpasswordparameters|readotherparameters|listaccounts)|lsass\.exe.*security account manager.*(readpasswordparameters|readotherparameters|listaccounts))"
        },
    },
    {
        "name": "Account discovery command",
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "tactic": "Discovery",
        "severity": "medium",
        "event_match": {"event_category": ["process"]},
        "regex_fields": {"command_line": r"(?i)\b(whoami|net\s+user|net\s+group|nltest|dsquery)\b"},
    },
    {
        "name": "System information discovery command",
        "technique_id": "T1082",
        "technique": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "medium",
        "event_match": {"event_category": ["process"]},
        "regex_fields": {"command_line": r"(?i)\b(hostname|systeminfo)\b"},
    },
    {
        "name": "System network configuration discovery command",
        "technique_id": "T1016",
        "technique": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "severity": "medium",
        "event_match": {"event_category": ["process"]},
        "regex_fields": {"command_line": r"(?i)\b(ipconfig|ifconfig|arp\s+-a|route\s+print)\b"},
    },
    {
        "name": "Persistence via registry run key",
        "technique_id": "T1547.001",
        "technique": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "high",
        "event_match": {"event_category": ["registry"]},
        "regex_fields": {"registry_key": r"(?i)(\\CurrentVersion\\Run|\\CurrentVersion\\RunOnce|Startup)"},
    },
    {
        "name": "Scheduled task creation",
        "technique_id": "T1053.005",
        "technique": "Scheduled Task",
        "tactic": "Persistence/Execution",
        "severity": "high",
        "event_match": {"event_category": ["process"], "process_name": ["schtasks.exe"]},
        "regex_fields": {"command_line": r"(?i)(/create|/change|/run)"},
    },
    {
        "name": "Suspicious outbound web connection from script/interpreter context",
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "severity": "medium",
        "event_match": {"event_category": ["network"]},
        "regex_fields": {"destination_port": r"^(80|443|8080|8443)$", "process_name": r"(?i)(powershell\.exe|pwsh\.exe|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|python\.exe|curl\.exe|wget\.exe)$"},
    },
    {
        "name": "Zeek DNS possible DGA-like domain pattern",
        "technique_id": "T1568.002",
        "technique": "Domain Generation Algorithms",
        "tactic": "Command and Control",
        "severity": "medium",
        "event_match": {"event_category": ["dns"]},
        "regex_fields": {"query": r"(?i)([a-z0-9]{20,}\.|[a-z0-9]{12,}[0-9]{3,}[a-z0-9]*\.)"},
        "not_regex_fields": {"query": r"(?i)(\.local\.?$|\.lan\.?$|\.home\.?$|\.arpa\.?$)"},
    },
    {
        "name": "Data staging archive creation",
        "technique_id": "T1560",
        "technique": "Archive Collected Data",
        "tactic": "Collection",
        "severity": "medium",
        "event_match": {"event_category": ["process"]},
        "regex_fields": {"command_line": r"(?i)(7z|rar|winrar|compress-archive|tar\s+-|zip)"},
    },
    {
        "name": "Possible high-volume outbound transfer",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "severity": "high",
        "event_match": {"event_category": ["network"]},
        "numeric_min": {"bytes_out": 5000000},
    },
]

TACTIC_ORDER = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Command and Control": 10,
    "Exfiltration": 11,
    "Impact": 12,
}

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    event_category: str
    host: str = "unknown"
    user: str = "unknown"
    process_name: str = ""
    command_line: str = ""
    parent_process: str = ""
    message: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: str = ""
    query: str = ""
    registry_key: str = ""
    file_path: str = ""
    bytes_out: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)
    detections: List[Dict[str, Any]] = field(default_factory=list)

    def as_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


def parse_time(value: Any) -> datetime:
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        # Zeek ts is usually epoch float.
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    for fmt in ISO_CANDIDATES:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        # Handles many ISO variants accepted by Python.
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def flatten_record(record: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten nested dictionaries so fields like process.command_line can be read."""
    out: Dict[str, Any] = {}
    for key, value in record.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.update(flatten_record(value, name))
        else:
            out[name] = value
    return out


def first_present(record: Dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    flat = flatten_record(record)
    lowered = {str(k).lower(): v for k, v in flat.items()}
    for key in keys:
        if key in flat and flat[key] not in (None, ""):
            return str(flat[key])
        lk = key.lower()
        if lk in lowered and lowered[lk] not in (None, ""):
            return str(lowered[lk])
    return default


def int_present(record: Dict[str, Any], keys: Iterable[str], default: int = 0) -> int:
    val = first_present(record, keys, "")
    if val == "":
        return default
    try:
        return int(float(val))
    except Exception:
        return default


def infer_category(record: Dict[str, Any], source_name: str) -> str:
    flat = flatten_record(record)
    event_id = first_present(flat, ["EventID", "event_id", "id"])
    log_type = source_name.lower()
    if "dns" in log_type or any(k in flat for k in ["query", "dns.question.name", "QueryName"]):
        return "dns"
    if "conn" in log_type or any(k in flat for k in ["id.orig_h", "id.resp_h", "dest_ip", "DestinationIp"]):
        return "network"
    if event_id in {"1", "4688"} or any(k in flat for k in ["Image", "ProcessName", "process_name", "CommandLine", "process.command_line"]):
        return "process"
    if event_id in {"12", "13", "14"} or any(k in flat for k in ["TargetObject", "registry_key"]):
        return "registry"
    if event_id in {"3", "5156"}:
        return "network"
    return first_present(flat, ["event_category", "category", "EventCategory"], "generic").lower()


def normalize_record(record: Dict[str, Any], source_name: str) -> NormalizedEvent:
    category = infer_category(record, source_name)
    ts = parse_time(first_present(record, ["UtcTime", "TimeCreated", "@timestamp", "timestamp", "ts", "TimeGenerated", "date", "datetime"]))
    image = first_present(record, ["Image", "ProcessName", "process_name", "process", "exe"])
    process_name = os.path.basename(image).lower() if image else first_present(record, ["process_name"], "").lower()
    command_line = first_present(record, ["CommandLine", "cmdline", "command_line", "process.command_line"])
    message = first_present(record, ["Message", "message", "RenderedDescription", "EventDescription"])
    host = first_present(record, ["Computer", "ComputerName", "Hostname", "host", "hostname", "agent.hostname", "id.orig_h"], "unknown")
    user = first_present(record, ["User", "TargetUserName", "SubjectUserName", "user", "username", "account"], "unknown")

    return NormalizedEvent(
        timestamp=ts,
        source=first_present(record, ["SourceName", "ProviderName", "Provider", "source"], source_name),
        event_category=category,
        host=host,
        user=user,
        process_name=process_name,
        command_line=command_line,
        parent_process=first_present(record, ["ParentImage", "ParentProcessName", "parent_process", "parent"]),
        message=message,
        source_ip=first_present(record, ["SourceIp", "src_ip", "source_ip", "id.orig_h", "src"]),
        destination_ip=first_present(record, ["DestinationIp", "dest_ip", "destination_ip", "id.resp_h", "dst"]),
        destination_port=first_present(record, ["DestinationPort", "dest_port", "destination_port", "id.resp_p", "dst_port"]),
        query=first_present(record, ["query", "QueryName", "dns.question.name"]),
        registry_key=first_present(record, ["TargetObject", "registry_key", "key"]),
        file_path=first_present(record, ["TargetFilename", "file_path", "path", "Filename"]),
        bytes_out=int_present(record, ["orig_bytes", "bytes_out", "sent_bytes", "SourceBytes"]),
        raw=record,
    )


def read_json_file(path: Path) -> Iterable[Dict[str, Any]]:
    text = path.read_text(errors="replace").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
        except json.JSONDecodeError:
            continue
    return records


def read_csv_file(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open(newline="", errors="replace") as f:
        return list(csv.DictReader(f))


def read_zeek_tsv_file(path: Path) -> Iterable[Dict[str, Any]]:
    """Parse standard Zeek TSV logs that contain #fields and #types headers."""
    fields: List[str] = []
    records: List[Dict[str, Any]] = []
    with path.open(errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields:
                values = line.split("\t")
                records.append({fields[i]: values[i] if i < len(values) else "" for i in range(len(fields))})
    return records


def read_log_file(path: Path) -> Iterable[Dict[str, Any]]:
    text = path.read_text(errors="replace", encoding="utf-8").lstrip()
    if text.startswith("#separator") or text.startswith("#fields"):
        return read_zeek_tsv_file(path)
    return read_json_file(path)


def evtx_xml_to_dict(xml_text: str) -> Dict[str, Any]:
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.fromstring(xml_text)
    out: Dict[str, Any] = {}
    system = root.find("e:System", ns)
    if system is not None:
        provider = system.find("e:Provider", ns)
        if provider is not None:
            out["Provider"] = provider.attrib.get("Name", "")
        event_id = system.find("e:EventID", ns)
        if event_id is not None and event_id.text:
            out["EventID"] = event_id.text
        computer = system.find("e:Computer", ns)
        if computer is not None and computer.text:
            out["Computer"] = computer.text
        time_created = system.find("e:TimeCreated", ns)
        if time_created is not None:
            out["TimeCreated"] = time_created.attrib.get("SystemTime", "")
    event_data = root.find("e:EventData", ns)
    if event_data is not None:
        for data in event_data.findall("e:Data", ns):
            name = data.attrib.get("Name")
            if name:
                out[name] = data.text or ""
    return out


def read_evtx_file(path: Path) -> Iterable[Dict[str, Any]]:
    if Evtx is None:
        raise RuntimeError("EVTX parsing requires optional dependency: pip install python-evtx")
    records = []
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                records.append(evtx_xml_to_dict(record.xml()))
            except Exception:
                continue
    return records


def load_events(paths: List[str]) -> List[NormalizedEvent]:
    events: List[NormalizedEvent] = []
    for item in paths:
        path = Path(item)
        files = list(path.rglob("*")) if path.is_dir() else [path]
        for f in files:
            if not f.is_file():
                continue
            suffix = f.suffix.lower()
            try:
                if suffix in [".json", ".jsonl", ".ndjson"]:
                    raw_records = read_json_file(f)
                elif suffix == ".log":
                    raw_records = read_log_file(f)
                elif suffix == ".csv":
                    raw_records = read_csv_file(f)
                elif suffix == ".evtx":
                    raw_records = read_evtx_file(f)
                else:
                    continue
                for rec in raw_records:
                    events.append(normalize_record(rec, f.name))
            except Exception as exc:
                print(f"[WARN] Failed to parse {f}: {exc}", file=sys.stderr)
    return sorted(events, key=lambda e: e.timestamp)


def event_matches_rule(event: NormalizedEvent, rule: Dict[str, Any]) -> bool:
    event_dict = asdict(event)
    for field_name, allowed_values in rule.get("event_match", {}).items():
        actual = str(event_dict.get(field_name, "")).lower()
        allowed = [str(x).lower() for x in allowed_values]
        if actual not in allowed:
            return False
    for field_name, pattern in rule.get("regex_fields", {}).items():
        actual = str(event_dict.get(field_name, ""))
        if not re.search(pattern, actual):
            return False
    for field_name, pattern in rule.get("not_regex_fields", {}).items():
        actual = str(event_dict.get(field_name, ""))
        if re.search(pattern, actual):
            return False
    for field_name, threshold in rule.get("numeric_min", {}).items():
        try:
            if int(event_dict.get(field_name, 0)) < int(threshold):
                return False
        except Exception:
            return False
    return True


def apply_detections(events: List[NormalizedEvent]) -> None:
    for event in events:
        for rule in DETECTION_RULES:
            if event_matches_rule(event, rule):
                event.detections.append({
                    "rule": rule["name"],
                    "technique_id": rule["technique_id"],
                    "technique": rule["technique"],
                    "tactic": rule["tactic"],
                    "severity": rule["severity"],
                    "risk": SEVERITY_WEIGHTS[rule["severity"]],
                })


def primary_entity(event: NormalizedEvent) -> Tuple[str, str]:
    # Host is primary; user is secondary. This keeps chains coherent even when
    # network events lack a user field.
    return (event.host or "unknown", event.user or "unknown")


def tactic_rank(tactic_text: str) -> int:
    ranks = []
    for part in re.split(r"/|,", tactic_text):
        part = part.strip()
        ranks.append(TACTIC_ORDER.get(part, 99))
    return min(ranks) if ranks else 99


def score_chain(events: List[NormalizedEvent]) -> int:
    detections = [d for e in events for d in e.detections]
    base = sum(int(d["risk"]) for d in detections)
    unique_techniques = len({d["technique_id"] for d in detections})
    unique_tactics = len({d["tactic"] for d in detections})
    sources = len({e.source for e in events})
    duration_minutes = max(1, int((events[-1].timestamp - events[0].timestamp).total_seconds() / 60)) if len(events) > 1 else 1

    multiplier = 1.0 + (0.12 * unique_techniques) + (0.08 * unique_tactics) + (0.05 * max(0, sources - 1))
    # Slight boost for compressed activity windows.
    if duration_minutes <= 30 and len(events) >= 3:
        multiplier += 0.15
    return min(100, int(base * multiplier / max(1, math.sqrt(len(events)))))


def correlate(events: List[NormalizedEvent], window_minutes: int) -> List[Dict[str, Any]]:
    suspicious = [e for e in events if e.detections]
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
    for event in suspicious:
        grouped[primary_entity(event)].append(event)

    chains: List[Dict[str, Any]] = []
    window = timedelta(minutes=window_minutes)
    chain_id = 1
    for (host, user), group_events in grouped.items():
        group_events.sort(key=lambda e: e.timestamp)
        current: List[NormalizedEvent] = []
        for event in group_events:
            if not current:
                current = [event]
                continue
            if event.timestamp - current[-1].timestamp <= window:
                current.append(event)
            else:
                if current:
                    chains.append(build_chain(chain_id, host, user, current))
                    chain_id += 1
                current = [event]
        if current:
            chains.append(build_chain(chain_id, host, user, current))
            chain_id += 1

    return sorted(chains, key=lambda c: c["risk_score"], reverse=True)


def build_chain(chain_id: int, host: str, user: str, events: List[NormalizedEvent]) -> Dict[str, Any]:
    techniques = []
    seen = set()
    for event in events:
        for det in event.detections:
            key = (det["technique_id"], det["rule"])
            if key not in seen:
                techniques.append(det)
                seen.add(key)
    ordered = sorted(techniques, key=lambda d: tactic_rank(d["tactic"]))
    return {
        "chain_id": chain_id,
        "host": host,
        "user": user,
        "start": events[0].timestamp.isoformat(),
        "end": events[-1].timestamp.isoformat(),
        "event_count": len(events),
        "risk_score": score_chain(events),
        "techniques": ordered,
        "events": [e.as_json() for e in events],
        "probable_sequence": [
            f"{d['tactic']}: {d['technique_id']} {d['technique']} ({d['rule']})" for d in ordered
        ],
    }


def write_timeline(events: List[NormalizedEvent], out_path: Path) -> None:
    rows = []
    for e in events:
        if not e.detections:
            continue
        rows.append({
            "timestamp": e.timestamp.isoformat(),
            "source": e.source,
            "host": e.host,
            "user": e.user,
            "category": e.event_category,
            "process": e.process_name,
            "command_line": e.command_line,
            "src_ip": e.source_ip,
            "dst_ip": e.destination_ip,
            "dst_port": e.destination_port,
            "query": e.query,
            "detections": "; ".join(f"{d['technique_id']} {d['technique']}" for d in e.detections),
        })
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["timestamp"])
        writer.writeheader()
        writer.writerows(rows)


def write_graph(chains: List[Dict[str, Any]], out_path: Path) -> None:
    lines = ["digraph attack_chains {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    for chain in chains:
        prev = None
        for idx, step in enumerate(chain["probable_sequence"]):
            node_id = f"c{chain['chain_id']}_{idx}"
            safe_label = step.replace('"', "'")
            lines.append(f'  {node_id} [label="Chain {chain["chain_id"]} | Risk {chain["risk_score"]}\\n{safe_label}"];')
            if prev:
                lines.append(f"  {prev} -> {node_id};")
            prev = node_id
    lines.append("}")
    out_path.write_text("\n".join(lines))


def write_html_report(chains: List[Dict[str, Any]], out_path: Path) -> None:
    def esc(x: Any) -> str:
        return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>ATT&CK Correlator Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:2rem;} table{border-collapse:collapse;width:100%;margin:1rem 0;} th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top;} .risk{font-weight:bold;} code{white-space:pre-wrap;}</style>",
        "</head><body><h1>ATT&CK-Based Detection Correlation Report</h1>",
    ]
    parts.append(f"<p>Total chains: {len(chains)}</p>")
    for chain in chains:
        parts.append(f"<h2>Chain {chain['chain_id']} | Host: {esc(chain['host'])} | User: {esc(chain['user'])} | Risk: <span class='risk'>{chain['risk_score']}</span></h2>")
        parts.append(f"<p>{esc(chain['start'])} to {esc(chain['end'])}; Events: {chain['event_count']}</p>")
        parts.append("<h3>Probable sequence</h3><ol>")
        for step in chain["probable_sequence"]:
            parts.append(f"<li>{esc(step)}</li>")
        parts.append("</ol><h3>Events</h3><table><tr><th>Time</th><th>Source</th><th>Category</th><th>Process</th><th>Command/Query</th><th>Detections</th></tr>")
        for event in chain["events"]:
            dets = "; ".join(f"{d['technique_id']} {d['technique']}" for d in event["detections"])
            cmd = event.get("command_line") or event.get("query") or event.get("registry_key") or event.get("destination_ip")
            parts.append(f"<tr><td>{esc(event['timestamp'])}</td><td>{esc(event['source'])}</td><td>{esc(event['event_category'])}</td><td>{esc(event.get('process_name',''))}</td><td><code>{esc(cmd)}</code></td><td>{esc(dets)}</td></tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    out_path.write_text("\n".join(parts))


def main() -> int:
    parser = argparse.ArgumentParser(description="ATT&CK-based multi-source detection correlator")
    parser.add_argument("inputs", nargs="+", help="Input files or directories containing JSON, JSONL, CSV, LOG, or EVTX files")
    parser.add_argument("-o", "--output", default="attack_correlator_output", help="Output directory")
    parser.add_argument("-w", "--window", type=int, default=60, help="Correlation window in minutes")
    parser.add_argument("--min-risk", type=int, default=0, help="Only include chains with risk score >= this value")
    args = parser.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    events = load_events(args.inputs)
    apply_detections(events)
    chains = correlate(events, args.window)
    chains = [c for c in chains if c["risk_score"] >= args.min_risk]

    (out_dir / "normalized_events.json").write_text(json.dumps([e.as_json() for e in events], indent=2))
    (out_dir / "attack_chains.json").write_text(json.dumps(chains, indent=2))
    write_timeline(events, out_dir / "timeline.csv")
    write_graph(chains, out_dir / "attack_graph.dot")
    write_html_report(chains, out_dir / "report.html")
    (out_dir / "validation_notes.txt").write_text(
        "This tool uses transparent heuristic detection rules mapped to MITRE ATT&CK technique IDs.\n"
        "The IDs/names were checked during preparation, but the rule logic is not an official MITRE detection and is not operationally validated.\n"
        "Use public datasets or lab telemetry to validate parsing, false positives, and correlation behavior before making claims.\n"
    )

    print(f"Loaded events: {len(events)}")
    print(f"Suspicious events: {sum(1 for e in events if e.detections)}")
    print(f"Attack chains: {len(chains)}")
    print(f"Output written to: {out_dir.resolve()}")
    if chains:
        print("\nTop chains:")
        for c in chains[:5]:
            print(f"  Chain {c['chain_id']} | Risk {c['risk_score']} | Host {c['host']} | User {c['user']} | Events {c['event_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
