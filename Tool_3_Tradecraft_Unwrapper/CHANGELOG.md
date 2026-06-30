# Changelog

## Unreleased

- No unreleased changes

## 1.0.0 - 2026-06-29

- Promoted Tradecraft Unwrapper to its initial stable release
- Added static, non-executing recursive transformation analysis
- Added Base64, URL-safe Base64, PowerShell EncodedCommand, hexadecimal, URL-percent, HTML-entity, and safe quoted-string reconstruction
- Added gzip, zlib, Bzip2, and XZ reconstruction
- Added conservative transformation detection and decoded-output plausibility checks
- Added maximum input-size, recursion-depth, recorded-stage, per-stage output, cumulative-output, transformation-preallocation, and XZ-memory controls
- Added trailing compressed-data detection and reporting
- Added unique-stage SHA-256 lineage with auditable duplicate-stage suppression warnings
- Added exact raw-stage `.bin` artifacts and text previews
- Added execution provenance and active resource-limit metadata
- Added observable-indicator extraction
- Added external JSON tradecraft rules
- Added conservative MITRE ATT&CK hypotheses with documented confidence values and mandatory confidence bases
- Added JSON, text, and safely escaped HTML reports
- Added output-directory isolation to prevent stale artifacts from being mixed with a new analysis
- Added synthetic validation samples
- Completed reproducibility, architecture, safety, testing, confidence-model, and AI-use documentation
- Added GitHub Actions validation for Python 3.10, 3.11, 3.12, and 3.13
- Confirmed all 64 automated tests pass
- Confirmed raw-stage artifact hashes match the recorded SHA-256 values

## 0.1.0 - 2026-06-29

- Added recursive transformation processing
- Added Base64 and URL-safe Base64 decoding
- Added PowerShell EncodedCommand decoding
- Added hexadecimal and URL-percent decoding
- Added HTML entity decoding
- Added safe quoted-string reconstruction
- Added gzip, zlib, Bzip2, and XZ support
- Added recursion and decoded-output limits
- Added stage SHA-256 hashes and transformation lineage
- Added indicator extraction
- Added external JSON tradecraft rules
- Added conservative MITRE ATT&CK hypotheses
- Added a documented confidence model
- Added mandatory confidence-basis validation
- Added JSON and text reports
- Added safely escaped HTML reports
- Added exact raw-stage artifacts and text previews
- Added synthetic samples
- Added the initial automated regression test suite
