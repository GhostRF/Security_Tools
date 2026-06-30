"""Tests for pre-allocation transformation limits."""

from __future__ import annotations

import base64
import lzma
import sys
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.transforms import (
    decode_base64_text,
    decode_hex_text,
    decode_html_entities,
    decode_xz_bytes,
    decode_powershell_encoded_command,
    decode_url_percent,
    reconstruct_string_concatenation,
)


class PreallocationLimitTests(unittest.TestCase):
    """Verify limits are checked before output is accepted."""

    def assert_limit_warning(
        self,
        candidates,
    ) -> None:
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].confidence,
            0,
        )
        self.assertTrue(
            candidates[0].warnings
        )
        self.assertIn(
            "configured",
            candidates[0].warnings[0].lower(),
        )

    def test_base64_limit(self) -> None:
        encoded = base64.b64encode(
            b"0123456789"
        ).decode("ascii")

        self.assert_limit_warning(
            decode_base64_text(
                encoded,
                maximum_output_bytes=5,
            )
        )

    def test_powershell_limit(self) -> None:
        payload = base64.b64encode(
            "Write-Output test".encode("utf-16le")
        ).decode("ascii")

        text = (
            "powershell.exe -EncodedCommand "
            + payload
        )

        self.assert_limit_warning(
            decode_powershell_encoded_command(
                text,
                maximum_output_bytes=8,
            )
        )

    def test_hexadecimal_limit(self) -> None:
        self.assert_limit_warning(
            decode_hex_text(
                "414243444546",
                maximum_output_bytes=3,
            )
        )

    def test_url_percent_limit(self) -> None:
        self.assert_limit_warning(
            decode_url_percent(
                "%41%42%43%44",
                maximum_output_bytes=3,
            )
        )

    def test_html_entity_limit(self) -> None:
        self.assert_limit_warning(
            decode_html_entities(
                "&lt;test&gt;",
                maximum_output_bytes=4,
            )
        )

    def test_concatenation_limit(self) -> None:
        self.assert_limit_warning(
            reconstruct_string_concatenation(
                '"abcd" + "efgh"',
                maximum_output_bytes=4,
            )
        )

    def test_xz_memory_limit(self) -> None:
        compressed = lzma.compress(
            b"A" * 4096,
            format=lzma.FORMAT_XZ,
        )

        candidates = decode_xz_bytes(
            compressed,
            maximum_output_bytes=8192,
            maximum_memory_bytes=1024,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].confidence,
            0,
        )
        self.assertTrue(
            candidates[0].warnings
        )
        self.assertIn(
            "memory limit",
            candidates[0].warnings[0].lower(),
        )


if __name__ == "__main__":
    unittest.main()
