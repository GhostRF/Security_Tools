"""Tests for Tradecraft Unwrapper transformation detection."""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.detectors import detect_transforms
from tradecraft_unwrapper_core.transforms import (
    decode_base64_text,
    decode_hex_text,
    decode_powershell_encoded_command,
    decode_url_percent,
)


class TransformationTests(unittest.TestCase):
    """Validate supported safe decoding transformations."""

    def test_standard_base64(self) -> None:
        original = b'Write-Output "Safe Base64 test"'
        encoded = base64.b64encode(original).decode("ascii")

        candidates = decode_base64_text(encoded)

        self.assertTrue(
            any(candidate.decoded == original for candidate in candidates)
        )

    def test_url_safe_base64(self) -> None:
        original = b"\xfb\xff\xefSafe"
        encoded = base64.urlsafe_b64encode(original).decode("ascii")

        candidates = decode_base64_text(encoded)

        self.assertTrue(
            any(candidate.decoded == original for candidate in candidates)
        )

    def test_powershell_encoded_command(self) -> None:
        command = 'Write-Output "Safe PowerShell test"'
        encoded = base64.b64encode(
            command.encode("utf-16le")
        ).decode("ascii")

        input_text = (
            "powershell.exe -NoProfile "
            f"-EncodedCommand {encoded}"
        )

        candidates = decode_powershell_encoded_command(input_text)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].decoded.decode("utf-16le"),
            command,
        )
        self.assertEqual(
            candidates[0].transform,
            "powershell-encoded-command",
        )

    def test_hexadecimal(self) -> None:
        original = b'Write-Output "Safe hex test"'
        encoded = original.hex()

        candidates = decode_hex_text(encoded)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].decoded, original)

    def test_url_percent_encoding(self) -> None:
        original = 'Write-Output "Safe URL test"'
        encoded = quote(original, safe="")

        candidates = decode_url_percent(encoded)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].decoded.decode("utf-8"),
            original,
        )

    def test_malformed_base64_is_rejected(self) -> None:
        candidates = decode_base64_text(
            "%%%this-is-not-valid-base64%%%"
        )

        self.assertEqual(candidates, [])

    def test_plaintext_is_not_misidentified(self) -> None:
        candidates = detect_transforms(
            'Write-Output "Normal unencoded text"'
        )

        self.assertEqual(candidates, [])

    def test_detector_prioritizes_powershell(self) -> None:
        command = 'Write-Output "Detector test"'
        encoded = base64.b64encode(
            command.encode("utf-16le")
        ).decode("ascii")

        candidates = detect_transforms(
            f"powershell -enc {encoded}"
        )

        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].transform,
            "powershell-encoded-command",
        )


if __name__ == "__main__":
    unittest.main()
