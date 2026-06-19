"""Input parsing helpers for exported configuration artifacts."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class KeyValueParseResult:
    values: Dict[str, str]
    malformed_lines: List[str]


@dataclass(frozen=True)
class PermissionParseResult:
    rows: List[Dict[str, str]]
    errors: List[str]


def read_text_file(path: Path) -> Optional[str]:
    """Return text, or None when the artifact does not exist."""
    if not path.exists() or not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def parse_key_value_config(text: str) -> KeyValueParseResult:
    """
    Parse simple key/value configuration files.

    Supported examples:
        PermitRootLogin no
        PASS_MAX_DAYS 90
        net.ipv4.ip_forward = 0
    """
    config: Dict[str, str] = {}
    malformed: List[str] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if not line:
            continue

        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
        else:
            parts = re.split(r"\s+", line, maxsplit=1)
            if len(parts) != 2:
                malformed.append(f"line {line_number}: {raw_line.strip()}")
                continue
            key, value = parts[0].strip(), parts[1].strip()

        if not key or not value:
            malformed.append(f"line {line_number}: {raw_line.strip()}")
            continue

        config[key.lower()] = value

    return KeyValueParseResult(values=config, malformed_lines=malformed)


def get_value(config: Dict[str, str], key: str) -> Optional[str]:
    return config.get(key.lower())


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_permissions_csv(path: Path) -> PermissionParseResult:
    required = {"path", "owner", "group", "mode"}
    rows: List[Dict[str, str]] = []
    errors: List[str] = []

    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            fieldnames = set(reader.fieldnames or [])

            missing = sorted(required - fieldnames)
            if missing:
                errors.append(
                    "missing required column(s): " + ", ".join(missing)
                )
                return PermissionParseResult(rows=rows, errors=errors)

            for line_number, row in enumerate(reader, start=2):
                normalized = {
                    key: str(row.get(key, "") or "").strip()
                    for key in required
                }
                if not normalized["path"] or not normalized["mode"]:
                    errors.append(
                        f"line {line_number}: path and mode are required"
                    )
                    continue
                rows.append(normalized)
    except (OSError, csv.Error) as exc:
        errors.append(str(exc))

    return PermissionParseResult(rows=rows, errors=errors)


def is_world_writable_mode(mode: str) -> bool:
    """
    Detect world-writable permissions from octal and symbolic representations.
    """
    clean = str(mode).strip()
    if not clean:
        return False

    if re.fullmatch(r"0?[0-7]{3,4}", clean):
        return bool(int(clean[-1]) & 0o2)

    symbolic = clean.rstrip("+.")

    if len(symbolic) >= 10 and symbolic[0] in "-dlcbps":
        permissions = symbolic[1:10]
        return permissions[7] == "w"

    if len(symbolic) >= 9:
        permissions = symbolic[:9]
        return permissions[7] == "w"

    return False
