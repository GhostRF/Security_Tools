"""Tests for conservative transformation detection."""

from __future__ import annotations

import base64
import gzip
import sys
import unittest
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.transforms import (
    decode_base64_text,
    decode_hex_text,
    printable_ratio,
)


class DetectionQualityTests(unittest.TestCase):
    """Verify ambiguous and implausible values are rejected."""

    def test_replacement_character_is_not_printable(
        self,
    ) -> None:
        ratio = printable_ratio(
            "\ufffdA\n"
        )

        self.assertAlmostEqual(
            ratio,
            2 / 3,
        )

    def test_ambiguous_hex_is_not_base64(
        self,
    ) -> None:
        candidates = decode_base64_text(
            "41424344"
        )

        self.assertEqual(
            candidates,
            [],
        )

    def test_implausible_hex_is_rejected(
        self,
    ) -> None:
        candidates = decode_hex_text(
            "deadbeef"
        )

        self.assertEqual(
            candidates,
            [],
        )

    def test_printable_base64_is_accepted(
        self,
    ) -> None:
        encoded = base64.b64encode(
            b"Write-Output training"
        ).decode("ascii")

        candidates = decode_base64_text(
            encoded
        )

        self.assertEqual(
            len(candidates),
            1,
        )

        self.assertEqual(
            candidates[0].decoded,
            b"Write-Output training",
        )

    def test_printable_hex_is_accepted(
        self,
    ) -> None:
        candidates = decode_hex_text(
            "41424344"
        )

        self.assertEqual(
            len(candidates),
            1,
        )

        self.assertEqual(
            candidates[0].decoded,
            b"ABCD",
        )

    def test_compressed_base64_is_accepted(
        self,
    ) -> None:
        compressed = gzip.compress(
            b"compressed training content"
        )

        encoded = base64.b64encode(
            compressed
        ).decode("ascii")

        candidates = decode_base64_text(
            encoded
        )

        self.assertEqual(
            len(candidates),
            1,
        )

        self.assertTrue(
            candidates[0].decoded.startswith(
                b"\x1f\x8b"
            )
        )


if __name__ == "__main__":
    unittest.main()
