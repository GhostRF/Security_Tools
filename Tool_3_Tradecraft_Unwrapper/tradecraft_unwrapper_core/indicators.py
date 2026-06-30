"""Extract observable indicators from analyzed stages."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Set, Tuple

from .models import Indicator, Stage


_URL_PATTERN = re.compile(
    r"\bhttps?://[^\s'\"<>]+",
    re.IGNORECASE,
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)

_IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w-])"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}\b",
    re.IGNORECASE,
)

_REGISTRY_PATTERN = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|"
    r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)"
    r"\\[^\r\n'\";]+",
    re.IGNORECASE,
)

_WINDOWS_PATH_PATTERN = re.compile(
    r"\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
    r"[^\\/:*?\"<>|\r\n]*",
    re.IGNORECASE,
)

_COMMAND_PATTERN = re.compile(
    r"\b(?:"
    r"powershell(?:\.exe)?|"
    r"pwsh(?:\.exe)?|"
    r"cmd(?:\.exe)?|"
    r"wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|"
    r"mshta(?:\.exe)?|"
    r"rundll32(?:\.exe)?|"
    r"regsvr32(?:\.exe)?|"
    r"certutil(?:\.exe)?|"
    r"curl(?:\.exe)?|"
    r"wget(?:\.exe)?"
    r")\b",
    re.IGNORECASE,
)


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def extract_indicators(stages: Iterable[Stage]) -> List[Indicator]:
    """Extract indicators only from content actually observed."""

    indicators: List[Indicator] = []
    seen: Set[Tuple[str, str, int]] = set()

    for stage in stages:
        matches: List[Tuple[str, str]] = []

        for value in _URL_PATTERN.findall(stage.text):
            matches.append(
                ("url", value.rstrip(".,);]"))
            )

        for value in _EMAIL_PATTERN.findall(stage.text):
            matches.append(("email", value))

        for value in _IPV4_PATTERN.findall(stage.text):
            if _is_valid_ipv4(value):
                matches.append(("ipv4", value))

        for value in _DOMAIN_PATTERN.findall(stage.text):
            normalized = value.lower()

            if normalized.endswith(
                (".exe", ".dll", ".txt", ".json", ".ps1")
            ):
                continue

            matches.append(("domain", normalized))

        for value in _REGISTRY_PATTERN.findall(stage.text):
            matches.append(("registry-path", value))

        for value in _WINDOWS_PATH_PATTERN.findall(stage.text):
            matches.append(("windows-path", value))

        for value in _COMMAND_PATTERN.findall(stage.text):
            matches.append(("command", value.lower()))

        for kind, value in matches:
            identity = (kind, value, stage.stage_id)

            if identity in seen:
                continue

            seen.add(identity)

            indicators.append(
                Indicator(
                    kind=kind,
                    value=value,
                    stage_id=stage.stage_id,
                )
            )

    return indicators
