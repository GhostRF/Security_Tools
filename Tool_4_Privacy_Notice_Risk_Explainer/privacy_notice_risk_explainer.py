#!/usr/bin/env python3
"""
Privacy Notice Risk Explainer

A local, rule-based privacy notice review tool that helps users and analysts
identify broad, vague, or high-impact data-use language in privacy notices.
It does not provide legal advice and does not determine compliance.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


__version__ = "1.1.0"


SEVERITY_POINTS = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 6,
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    patterns: list[str]
    explanation: str
    recommendation: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: str
    explanation: str
    recommendation: str


RULES: list[Rule] = [
    Rule(
        "PN-001",
        "Precise location or geolocation collection",
        "high",
        "Data Collection",
        [r"\bprecise\s+location\b", r"\bgeolocation\b", r"\bgps\b", r"\blocation\s+data\b"],
        "The notice appears to describe collection or use of precise location information.",
        "State whether location collection is optional, when it occurs, how long it is retained, and how users can disable it.",
    ),
    Rule(
        "PN-002",
        "Biometric information collection",
        "critical",
        "Sensitive Data",
        [r"\bbiometric\b", r"\bface\s+scan\b", r"\bfingerprint\b", r"\bvoiceprint\b"],
        "The notice appears to reference biometric information, which can create elevated privacy risk.",
        "Explain the exact biometric data collected, purpose, retention period, sharing practices, and deletion process.",
    ),
    Rule(
        "PN-003",
        "Contacts, photos, or device-content access",
        "high",
        "Sensitive Data",
        [r"\bcontacts\b", r"\baddress\s+book\b", r"\bphotos\b", r"\bmessages\b", r"\bfiles\b"],
        "The notice appears to reference access to personal content or user device data.",
        "Clarify what content is accessed, whether access is optional, and whether content is uploaded or only processed locally.",
    ),
    Rule(
        "PN-004",
        "Device identifiers or tracking identifiers",
        "medium",
        "Tracking",
        [r"\bdevice\s+identifier", r"\badvertising\s+id", r"\bcookie", r"\btracking\s+technolog"],
        "The notice appears to reference device identifiers, cookies, or tracking technologies.",
        "Describe the tracking purpose, retention period, user controls, and whether tracking is used across services.",
    ),
    Rule(
        "PN-005",
        "Third-party sharing",
        "high",
        "Sharing",
        [r"\bthird[-\s]?part", r"\bpartners\b", r"\baffiliates\b", r"\bservice\s+providers\b", r"\bdata\s+brokers\b"],
        "The notice appears to describe sharing with outside organizations.",
        "Name the categories of recipients, state the reason for sharing, and provide opt-out or deletion instructions where available.",
    ),
    Rule(
        "PN-006",
        "Advertising, profiling, or targeted advertising",
        "high",
        "Advertising and Profiling",
        [r"\btargeted\s+advertising\b", r"\bprofiling\b", r"\badvertising\s+network", r"\bpersonalized\s+ads\b"],
        "The notice appears to describe advertising, profiling, or personalization based on user data.",
        "Explain what data is used for profiling, whether users can opt out, and whether data is shared for advertising.",
    ),
    Rule(
        "PN-007",
        "Sell or share personal information",
        "critical",
        "Sharing",
        [r"\bsell\s+(your\s+)?personal\s+information\b", r"\bsell\s+or\s+share\b", r"\bshare\s+personal\s+information\b"],
        "The notice appears to include selling or sharing personal information.",
        "Clearly describe what is sold or shared, with whom, why, and how users can opt out.",
    ),
    Rule(
        "PN-008",
        "Vague retention language",
        "medium",
        "Retention",
        [r"\bas\s+long\s+as\s+necessary\b", r"\bfor\s+business\s+purposes\b", r"\bindefinitely\b", r"\bretain\s+.*necessary\b"],
        "The notice appears to use broad or vague data-retention language.",
        "Provide specific retention periods or clear criteria for deletion.",
    ),
    Rule(
        "PN-009",
        "Data combined from multiple sources",
        "medium",
        "Data Combination",
        [r"\bcombine\s+.*data\b", r"\bcombine\s+.*information\b", r"\binformation\s+from\s+third\s+parties\b"],
        "The notice appears to describe combining user data with other sources.",
        "Explain which sources are combined, why, and whether users can limit this processing.",
    ),
    Rule(
        "PN-010",
        "Children or minors referenced",
        "high",
        "Children and Minors",
        [r"\bchildren\b", r"\bunder\s+13\b", r"\bminors\b", r"\bteen\b"],
        "The notice appears to reference children, minors, or teen users.",
        "Clarify age restrictions, parental consent, collection limits, and deletion procedures for minors.",
    ),
    Rule(
        "PN-011",
        "Broad service improvement or personalization purpose",
        "medium",
        "Purpose Limitation",
        [
            r"\bimprove\s+our\s+services\b",
            r"\benhance\s+our\s+services\b",
            r"\bpersonalize\s+your\s+experience\b",
            r"\bresearch\s+and\s+development\b",
        ],
        "The notice appears to use broad purpose language that may not clearly limit how personal information is used.",
        "Clarify the specific purposes, data types involved, and whether users can limit this processing.",
    ),
    Rule(
        "PN-012",
        "Broad legal or discretionary language",
        "medium",
        "Ambiguous Legal Language",
        [
            r"\bincluding\s+but\s+not\s+limited\s+to\b",
            r"\bas\s+permitted\s+by\s+law\b",
            r"\bat\s+our\s+discretion\b",
            r"\bfrom\s+time\s+to\s+time\b",
            r"\bmay\s+disclose\s+.*necessary\b",
        ],
        "The notice appears to use open-ended legal language that may be difficult for users to interpret.",
        "Replace broad discretionary wording with specific examples, limits, and user-facing choices where possible.",
    ),

]


def count_syllables(word: str) -> int:
    cleaned = re.sub(r"[^a-z]", "", word.lower())
    if not cleaned:
        return 0

    groups = re.findall(r"[aeiouy]+", cleaned)
    count = len(groups)

    if cleaned.endswith("e") and count > 1:
        count -= 1

    return max(count, 1)


def readability_metrics(text: str) -> dict:
    words = re.findall(r"[A-Za-z]+(?:'[A-Za-z]+)?", text)
    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]

    word_count = len(words)
    sentence_count = max(len(sentences), 1)
    syllable_count = sum(count_syllables(word) for word in words)

    if word_count == 0:
        return {
            "word_count": 0,
            "sentence_count": 0,
            "flesch_reading_ease": 0.0,
            "flesch_kincaid_grade": 0.0,
            "readability_label": "No readable text",
        }

    words_per_sentence = word_count / sentence_count
    syllables_per_word = syllable_count / word_count

    reading_ease = 206.835 - (1.015 * words_per_sentence) - (84.6 * syllables_per_word)
    grade = (0.39 * words_per_sentence) + (11.8 * syllables_per_word) - 15.59

    if reading_ease >= 70:
        label = "Plain language"
    elif reading_ease >= 50:
        label = "Moderate"
    else:
        label = "Difficult"

    return {
        "word_count": word_count,
        "sentence_count": len(sentences),
        "flesch_reading_ease": round(reading_ease, 2),
        "flesch_kincaid_grade": round(max(grade, 0), 2),
        "readability_label": label,
    }


def make_evidence(text: str, start: int, end: int) -> str:
    left = max(0, start - 80)
    right = min(len(text), end + 80)
    snippet = re.sub(r"\s+", " ", text[left:right]).strip()

    if left > 0:
        snippet = "..." + snippet
    if right < len(text):
        snippet = snippet + "..."

    return snippet


def find_rule_match(text: str, rule: Rule) -> Finding | None:
    for pattern in rule.patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                category=rule.category,
                evidence=make_evidence(text, match.start(), match.end()),
                explanation=rule.explanation,
                recommendation=rule.recommendation,
            )

    return None


def classify_risk(score: int) -> str:
    if score >= 18:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 4:
        return "MODERATE"
    return "LOW"



def load_custom_rules(path: Path) -> list[Rule]:
    """Load optional custom privacy rules from a JSON file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{path}: could not read file: {exc}") from exc

    entries = raw.get("rules") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON list or an object with a 'rules' list")

    required = {
        "rule_id",
        "title",
        "severity",
        "category",
        "patterns",
        "explanation",
        "recommendation",
    }

    custom_rules: list[Rule] = []

    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: rule {index} must be a JSON object")

        missing = sorted(required - set(entry))
        if missing:
            raise ValueError(f"{path}: rule {index} missing required fields: {', '.join(missing)}")

        severity = str(entry["severity"]).strip().lower()
        if severity not in SEVERITY_POINTS:
            raise ValueError(f"{path}: rule {index} has unsupported severity '{entry['severity']}'")

        patterns_raw = entry["patterns"]
        if not isinstance(patterns_raw, list):
            raise ValueError(f"{path}: rule {index} patterns must be a list")

        patterns = [str(pattern).strip() for pattern in patterns_raw if str(pattern).strip()]
        if not patterns:
            raise ValueError(f"{path}: rule {index} must include at least one pattern")

        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"{path}: rule {index} has invalid regex pattern '{pattern}': {exc}") from exc

        custom_rules.append(
            Rule(
                rule_id=str(entry["rule_id"]).strip(),
                title=str(entry["title"]).strip(),
                severity=severity,
                category=str(entry["category"]).strip(),
                patterns=patterns,
                explanation=str(entry["explanation"]).strip(),
                recommendation=str(entry["recommendation"]).strip(),
            )
        )

    return custom_rules


def analyze_notice(
    text: str,
    source_name: str,
    rules: list[Rule] | None = None,
    custom_rules_loaded: int = 0,
) -> dict:
    findings: list[Finding] = []
    active_rules = list(rules) if rules is not None else RULES

    for rule in active_rules:
        finding = find_rule_match(text, rule)
        if finding:
            findings.append(finding)

    risk_score = sum(SEVERITY_POINTS[f.severity] for f in findings)
    severity_counts = {severity: 0 for severity in SEVERITY_POINTS}

    for finding in findings:
        severity_counts[finding.severity] += 1

    return {
        "tool_name": "Privacy Notice Risk Explainer",
        "tool_version": __version__,
        "analysis_mode": "local-rule-based-static-review",
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source": source_name,
        "rules_used": len(active_rules),
        "custom_rules_loaded": custom_rules_loaded,
        "risk_score": risk_score,
        "risk_level": classify_risk(risk_score),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "readability": readability_metrics(text),
        "findings": [asdict(finding) for finding in findings],
        "disclaimer": "This tool supports privacy and security review. It is not legal advice and does not determine regulatory compliance.",
    }


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json_report(result: dict, output_dir: Path) -> Path:
    path = output_dir / "analysis.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_text_report(result: dict, output_dir: Path) -> Path:
    path = output_dir / "summary.txt"

    lines = [
        f"{result['tool_name']} v{result['tool_version']}",
        "",
        f"Source: {result['source']}",
        f"Risk level: {result['risk_level']}",
        f"Risk score: {result['risk_score']}",
        f"Findings: {result['finding_count']}",
        "",
        "Severity counts:",
    ]

    for severity, count in result["severity_counts"].items():
        lines.append(f"- {severity}: {count}")

    readability = result["readability"]
    lines.extend(
        [
            "",
            "Readability:",
            f"- Label: {readability['readability_label']}",
            f"- Flesch reading ease: {readability['flesch_reading_ease']}",
            f"- Flesch-Kincaid grade: {readability['flesch_kincaid_grade']}",
            "",
            "Findings:",
        ]
    )

    if not result["findings"]:
        lines.append("- No rule-based privacy risk findings were identified.")
    else:
        for finding in result["findings"]:
            lines.extend(
                [
                    "",
                    f"[{finding['severity'].upper()}] {finding['rule_id']} - {finding['title']}",
                    f"Category: {finding['category']}",
                    f"Evidence: {finding['evidence']}",
                    f"What this means: {finding['explanation']}",
                    f"Suggested improvement: {finding['recommendation']}",
                ]
            )

    lines.extend(["", result["disclaimer"], ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_report(result: dict, output_dir: Path) -> Path:
    path = output_dir / "report.html"

    finding_blocks = []
    if result["findings"]:
        for finding in result["findings"]:
            finding_blocks.append(
                f"""
                <section class="finding">
                  <h3>{html.escape(finding['severity'].upper())}: {html.escape(finding['rule_id'])} - {html.escape(finding['title'])}</h3>
                  <p><strong>Category:</strong> {html.escape(finding['category'])}</p>
                  <p><strong>Evidence:</strong> {html.escape(finding['evidence'])}</p>
                  <p><strong>What this means:</strong> {html.escape(finding['explanation'])}</p>
                  <p><strong>Suggested improvement:</strong> {html.escape(finding['recommendation'])}</p>
                </section>
                """
            )
    else:
        finding_blocks.append("<p>No rule-based privacy risk findings were identified.</p>")

    readability = result["readability"]
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Privacy Notice Risk Explainer Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }}
.summary {{ border: 1px solid #ccc; padding: 1rem; margin-bottom: 1rem; }}
.finding {{ border-top: 1px solid #ddd; padding-top: 1rem; margin-top: 1rem; }}
code {{ background: #f4f4f4; padding: 0.1rem 0.3rem; }}
</style>
</head>
<body>
<h1>{html.escape(result['tool_name'])} v{html.escape(result['tool_version'])}</h1>
<div class="summary">
<p><strong>Source:</strong> {html.escape(result['source'])}</p>
<p><strong>Risk level:</strong> {html.escape(result['risk_level'])}</p>
<p><strong>Risk score:</strong> {result['risk_score']}</p>
<p><strong>Findings:</strong> {result['finding_count']}</p>
<p><strong>Readability:</strong> {html.escape(readability['readability_label'])}
  | Flesch reading ease: {readability['flesch_reading_ease']}
  | Flesch-Kincaid grade: {readability['flesch_kincaid_grade']}</p>
</div>
<h2>Findings</h2>
{''.join(finding_blocks)}
<hr>
<p><em>{html.escape(result['disclaimer'])}</em></p>
</body>
</html>
"""
    path.write_text(body, encoding="utf-8")
    return path


def write_csv_report(result: dict, output_dir: Path) -> Path:
    path = output_dir / "findings.csv"

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "rule_id",
                "title",
                "severity",
                "category",
                "evidence",
                "explanation",
                "recommendation",
            ],
        )
        writer.writeheader()
        for finding in result["findings"]:
            writer.writerow(finding)

    return path


def write_reports(result: dict, output_dir: Path, report_format: str) -> list[Path]:
    ensure_output_dir(output_dir)

    writers = {
        "json": write_json_report,
        "text": write_text_report,
        "html": write_html_report,
        "csv": write_csv_report,
    }

    if report_format == "all":
        selected = ["json", "text", "html", "csv"]
    else:
        selected = [report_format]

    return [writers[item](result, output_dir) for item in selected]


def print_console_summary(result: dict, written_paths: Iterable[Path]) -> None:
    print(f"{result['tool_name']} v{result['tool_version']}")
    print(f"Source: {result['source']}")
    print(f"Risk level: {result['risk_level']}")
    print(f"Risk score: {result['risk_score']}")
    print(f"Findings: {result['finding_count']}")
    if result.get("custom_rules_loaded"):
        print(f"Custom rules loaded: {result['custom_rules_loaded']}")

    readability = result["readability"]
    print(
        "Readability: "
        f"{readability['readability_label']} "
        f"(grade {readability['flesch_kincaid_grade']})"
    )

    if result["findings"]:
        print("\nTop findings:")
        for finding in result["findings"][:5]:
            print(f"- [{finding['severity'].upper()}] {finding['title']}")
    else:
        print("\nNo rule-based privacy risk findings were identified.")

    print("\nReports written:")
    for path in written_paths:
        print(f"- {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain privacy-notice risk indicators in plain language."
    )
    parser.add_argument(
        "notice",
        nargs="?",
        help="Path to a privacy notice, consent statement, permission disclosure, or policy text file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output/privacy-notice-analysis",
        help="Output directory for reports.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["all", "json", "text", "html", "csv"],
        default="all",
        dest="report_format",
        help="Report format to write. Default: all.",
    )
    parser.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Optional JSON file with custom privacy rules. May be used more than once.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"privacy_notice_risk_explainer.py {__version__}")
        return 0

    if not args.notice:
        parser.error("the following arguments are required: notice")

    notice_path = Path(args.notice)

    if not notice_path.exists():
        print(f"ERROR: input file not found: {notice_path}", file=sys.stderr)
        return 2

    try:
        text = notice_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: could not read input file: {exc}", file=sys.stderr)
        return 2

    if not text.strip():
        print("ERROR: input file is empty", file=sys.stderr)
        return 2

    custom_rules: list[Rule] = []
    for rule_file in args.rules:
        rule_path = Path(rule_file)
        if not rule_path.exists():
            print(f"ERROR: custom rule file not found: {rule_path}", file=sys.stderr)
            return 2
        try:
            custom_rules.extend(load_custom_rules(rule_path))
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    active_rules = [*RULES, *custom_rules]
    result = analyze_notice(text, str(notice_path), active_rules, len(custom_rules))
    written_paths = write_reports(result, Path(args.output), args.report_format)
    print_console_summary(result, written_paths)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
