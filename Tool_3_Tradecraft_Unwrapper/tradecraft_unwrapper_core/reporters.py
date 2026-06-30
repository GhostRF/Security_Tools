"""Report and artifact generation for Tradecraft Unwrapper."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import List

from .models import AnalysisResult, Stage


def _stage_stem(
    stage_id: int,
    transform: str,
) -> str:
    """Create a filesystem-safe stage artifact name."""

    safe_transform = "".join(
        character
        if character.isalnum()
        or character in "-_"
        else "_"
        for character in transform
    )

    return (
        f"stage_{stage_id:02d}_"
        f"{safe_transform}"
    )


def _collect_warnings(
    result: AnalysisResult,
) -> List[str]:
    """Collect analysis-level and stage-level warnings."""

    warnings = list(result.warnings)

    for stage in result.stages:
        warnings.extend(
            f"Stage {stage.stage_id}: {warning}"
            for warning in stage.warnings
        )

    return warnings


def render_summary(
    result: AnalysisResult,
) -> str:
    """Render a human-readable analysis summary."""

    lines: List[str] = [
        "Tradecraft Unwrapper Analysis",
        f"Source: {result.source}",
        f"Root SHA-256: {result.root_sha256}",
        (
            "Tool version: "
            f"{result.provenance.get('tool_version', 'Unknown')}"
        ),
        (
            "Generated UTC: "
            f"{result.provenance.get('generated_at_utc', 'Unknown')}"
        ),
        (
            "Python version: "
            f"{result.provenance.get('python_version', 'Unknown')}"
        ),
        (
            "Analysis mode: "
            f"{result.provenance.get('analysis_mode', 'Unknown')}"
        ),
        (
            "Lineage policy: "
            f"{result.provenance.get('lineage_policy', 'Unknown')}"
        ),
        (
            "Configured limits: "
            + json.dumps(
                result.provenance.get("limits", {}),
                sort_keys=True,
            )
        ),
        f"Unique stages recorded: {len(result.stages)}",
        (
            "Derived stages: "
            f"{max(0, len(result.stages) - 1)}"
        ),
        (
            "Indicators extracted: "
            f"{len(result.indicators)}"
        ),
        (
            "Tradecraft findings: "
            f"{len(result.findings)}"
        ),
        "",
        "Recorded stage lineage "
        "(duplicate SHA-256 outputs suppressed):",
    ]

    for stage in result.stages:
        parent = (
            "none"
            if stage.parent_id is None
            else str(stage.parent_id)
        )

        lines.append(
            f"  Stage {stage.stage_id}: "
            f"parent={parent}, "
            f"depth={stage.depth}, "
            f"transform={stage.transform}, "
            f"transform_confidence={stage.confidence}, "
            f"bytes={stage.output_size}, "
            f"sha256={stage.output_sha256}"
        )

    if result.indicators:
        lines.extend(["", "Indicators:"])

        for indicator in result.indicators:
            lines.append(
                f"  [{indicator.kind}] "
                f"stage={indicator.stage_id} "
                f"{indicator.value}"
            )

    if result.findings:
        lines.extend(
            ["", "Tradecraft findings:"]
        )

        for finding in result.findings:
            attack = (
                f"{finding.attack_id} "
                f"{finding.attack_name}"
                if finding.attack_id
                else "No ATT&CK mapping"
            )

            lines.append(
                f"  [{finding.severity.upper()}] "
                f"{finding.rule_id}: "
                f"{finding.title}"
            )

            lines.append(
                f"    Confidence: "
                f"{finding.confidence}"
            )

            lines.append(
                f"    Confidence basis: "
                f"{finding.confidence_basis}"
            )

            lines.append(
                f"    ATT&CK hypothesis: "
                f"{attack}"
            )

            lines.append(
                f"    Description: "
                f"{finding.description}"
            )

            for evidence in finding.evidence:
                lines.append(
                    f"    Evidence: {evidence}"
                )

    warnings = _collect_warnings(result)

    if warnings:
        lines.extend(["", "Warnings:"])

        lines.extend(
            f"  - {warning}"
            for warning in warnings
        )

    return "\n".join(lines) + "\n"


def _stage_html(
    stage: Stage,
) -> str:
    """Render one safely escaped HTML stage section."""

    parent = (
        "none"
        if stage.parent_id is None
        else str(stage.parent_id)
    )

    stem = _stage_stem(
        stage.stage_id,
        stage.transform,
    )

    preview = stage.text

    if len(preview) > 4_000:
        preview = (
            preview[:4_000]
            + "\n\n[Preview truncated]"
        )

    warning_html = ""

    if stage.warnings:
        items = "".join(
            f"<li>{escape(warning)}</li>"
            for warning in stage.warnings
        )

        warning_html = (
            "<div class=\"warnings\">"
            "<strong>Stage warnings</strong>"
            f"<ul>{items}</ul>"
            "</div>"
        )

    return f"""
    <section class="card">
      <h3>Stage {stage.stage_id}: {escape(stage.transform)}</h3>
      <dl>
        <dt>Parent</dt><dd>{escape(parent)}</dd>
        <dt>Depth</dt><dd>{stage.depth}</dd>
        <dt>Transform confidence</dt><dd>{stage.confidence}</dd>
        <dt>Encoding</dt><dd>{escape(stage.text_encoding)}</dd>
        <dt>Output size</dt><dd>{stage.output_size} bytes</dd>
        <dt>Printable ratio</dt><dd>{stage.printable_ratio:.3f}</dd>
        <dt>SHA-256</dt><dd><code>{escape(stage.output_sha256)}</code></dd>
        <dt>Evidence</dt><dd>{escape(stage.evidence)}</dd>
      </dl>
      <p>
        <a href="stages/{stem}.bin">Raw bytes</a>
        |
        <a href="stages/{stem}.txt">Text preview</a>
      </p>
      {warning_html}
      <details>
        <summary>Text preview</summary>
        <pre>{escape(preview)}</pre>
      </details>
    </section>
    """


def render_html(
    result: AnalysisResult,
) -> str:
    """Render a self-contained, safely escaped HTML report."""

    stage_sections = "".join(
        _stage_html(stage)
        for stage in result.stages
    )

    if result.indicators:
        indicator_rows = "".join(
            "<tr>"
            f"<td>{escape(indicator.kind)}</td>"
            f"<td>{indicator.stage_id}</td>"
            f"<td><code>{escape(indicator.value)}</code></td>"
            "</tr>"
            for indicator in result.indicators
        )
    else:
        indicator_rows = (
            "<tr><td colspan=\"3\">"
            "No indicators extracted."
            "</td></tr>"
        )

    if result.findings:
        finding_sections = "".join(
            f"""
            <section class="card finding {escape(finding.severity)}">
              <h3>
                {escape(finding.rule_id)}:
                {escape(finding.title)}
              </h3>
              <p>
                <strong>Severity:</strong>
                {escape(finding.severity)}
              </p>
              <p>
                <strong>Confidence:</strong>
                {finding.confidence}
              </p>
              <p>
                <strong>Confidence basis:</strong>
                {escape(finding.confidence_basis)}
              </p>
              <p>
                <strong>ATT&amp;CK hypothesis:</strong>
                {escape(
                    (
                        f"{finding.attack_id} "
                        f"{finding.attack_name}"
                    )
                    if finding.attack_id
                    else "No ATT&CK mapping"
                )}
              </p>
              <p>{escape(finding.description)}</p>
              <ul>
                {
                    "".join(
                        f"<li>{escape(evidence)}</li>"
                        for evidence in finding.evidence
                    )
                }
              </ul>
            </section>
            """
            for finding in result.findings
        )
    else:
        finding_sections = (
            "<p>No tradecraft findings generated.</p>"
        )

    warnings = _collect_warnings(result)

    if warnings:
        warning_items = "".join(
            f"<li>{escape(warning)}</li>"
            for warning in warnings
        )
    else:
        warning_items = (
            "<li>No warnings generated.</li>"
        )

    ruleset_name = result.ruleset.get(
        "name",
        "Unknown",
    )

    ruleset_version = result.ruleset.get(
        "version",
        "Unknown",
    )

    tool_version = result.provenance.get(
        "tool_version",
        "Unknown",
    )

    generated_at_utc = result.provenance.get(
        "generated_at_utc",
        "Unknown",
    )

    python_version = result.provenance.get(
        "python_version",
        "Unknown",
    )

    analysis_mode = result.provenance.get(
        "analysis_mode",
        "Unknown",
    )

    lineage_policy = result.provenance.get(
        "lineage_policy",
        "Unknown",
    )

    limits_json = escape(
        json.dumps(
            result.provenance.get("limits", {}),
            indent=2,
            sort_keys=True,
        )
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >
  <title>Tradecraft Unwrapper Analysis</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      background: #f4f6f8;
      color: #1f2933;
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 2rem;
    }}
    h1, h2, h3 {{
      color: #102a43;
    }}
    .card {{
      background: white;
      border: 1px solid #d9e2ec;
      border-radius: 8px;
      margin: 1rem 0;
      padding: 1rem 1.25rem;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 0.75rem;
    }}
    .metric {{
      background: white;
      border: 1px solid #d9e2ec;
      border-radius: 8px;
      padding: 1rem;
    }}
    dl {{
      display: grid;
      grid-template-columns: 150px 1fr;
      gap: 0.4rem 1rem;
    }}
    dt {{
      font-weight: 600;
    }}
    dd {{
      margin: 0;
      overflow-wrap: anywhere;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
    }}
    th, td {{
      border: 1px solid #d9e2ec;
      padding: 0.6rem;
      text-align: left;
    }}
    pre {{
      overflow-x: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #102a43;
      color: #f0f4f8;
      padding: 1rem;
      border-radius: 6px;
    }}
    code {{
      overflow-wrap: anywhere;
    }}
    .finding.low {{
      border-left: 6px solid #627d98;
    }}
    .finding.medium {{
      border-left: 6px solid #d69e2e;
    }}
    .finding.high,
    .finding.critical {{
      border-left: 6px solid #c53030;
    }}
    .warnings {{
      background: #fffaf0;
      border: 1px solid #f6ad55;
      padding: 0.75rem;
      border-radius: 6px;
    }}
  </style>
</head>
<body>
<main>
  <h1>Tradecraft Unwrapper Analysis</h1>

  <section class="card">
    <p><strong>Source:</strong> {escape(result.source)}</p>
    <p>
      <strong>Root SHA-256:</strong>
      <code>{escape(result.root_sha256)}</code>
    </p>
    <p>
      <strong>Ruleset:</strong>
      {escape(ruleset_name)}
      v{escape(ruleset_version)}
    </p>
    <p>
      <strong>Tool version:</strong>
      {escape(str(tool_version))}
    </p>
    <p>
      <strong>Generated UTC:</strong>
      {escape(str(generated_at_utc))}
    </p>
    <p>
      <strong>Python version:</strong>
      {escape(str(python_version))}
    </p>
    <p>
      <strong>Analysis mode:</strong>
      {escape(str(analysis_mode))}
    </p>
    <p>
      <strong>Lineage policy:</strong>
      {escape(str(lineage_policy))}
    </p>
    <details>
      <summary>Configured analysis limits</summary>
      <pre>{limits_json}</pre>
    </details>
  </section>

  <section class="summary">
    <div class="metric">
      <strong>Unique stages</strong><br>
      {len(result.stages)}
    </div>
    <div class="metric">
      <strong>Derived stages</strong><br>
      {max(0, len(result.stages) - 1)}
    </div>
    <div class="metric">
      <strong>Indicators</strong><br>
      {len(result.indicators)}
    </div>
    <div class="metric">
      <strong>Findings</strong><br>
      {len(result.findings)}
    </div>
  </section>

  <h2>Recorded stage lineage</h2>
  {stage_sections}

  <h2>Indicators</h2>
  <table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Stage</th>
        <th>Value</th>
      </tr>
    </thead>
    <tbody>
      {indicator_rows}
    </tbody>
  </table>

  <h2>Tradecraft findings</h2>
  {finding_sections}

  <h2>Warnings</h2>
  <section class="card">
    <ul>{warning_items}</ul>
  </section>
</main>
</body>
</html>
"""


def _prepare_output_directory(
    output_directory: Path,
) -> None:
    """Require a new or empty output directory.

    A repository placeholder named .gitkeep is permitted.
    Existing reports or stage artifacts are never silently
    overwritten because they may belong to an earlier analysis.
    """

    if output_directory.exists():
        if not output_directory.is_dir():
            raise OSError(
                "The output path exists but is not a "
                f"directory: {output_directory}"
            )

        existing_entries = sorted(
            entry.name
            for entry in output_directory.iterdir()
            if entry.name != ".gitkeep"
        )

        if existing_entries:
            preview = ", ".join(
                existing_entries[:5]
            )

            if len(existing_entries) > 5:
                preview += ", ..."

            raise OSError(
                "The output directory is not empty. "
                "Choose a new directory or remove the "
                "previous analysis artifacts first. "
                f"Existing entries: {preview}"
            )
    else:
        output_directory.mkdir(
            parents=True,
            exist_ok=False,
        )


def write_reports(
    result: AnalysisResult,
    output_directory: Path,
) -> None:
    """Write reports, text previews, and exact raw stage bytes."""

    _prepare_output_directory(
        output_directory
    )

    stages_directory = (
        output_directory
        / "stages"
    )

    stages_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        output_directory
        / "analysis.json"
    ).write_text(
        json.dumps(
            result.to_dict(),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    (
        output_directory
        / "summary.txt"
    ).write_text(
        render_summary(result),
        encoding="utf-8",
    )

    (
        output_directory
        / "report.html"
    ).write_text(
        render_html(result),
        encoding="utf-8",
    )

    for stage in result.stages:
        if stage.stage_id not in result.stage_bytes:
            raise OSError(
                "Raw bytes were unavailable for "
                f"stage {stage.stage_id}."
            )

        stem = _stage_stem(
            stage.stage_id,
            stage.transform,
        )

        (
            stages_directory
            / f"{stem}.bin"
        ).write_bytes(
            result.stage_bytes[
                stage.stage_id
            ]
        )

        (
            stages_directory
            / f"{stem}.txt"
        ).write_text(
            stage.text,
            encoding="utf-8",
        )
