"""Tests for compression and safe text reconstruction."""

from __future__ import annotations

import base64
import bz2
import gzip
import lzma
import sys
import unittest
import zlib
from pathlib import Path

TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.pipeline import (
    AnalyzerConfig,
    analyze_bytes,
)
from tradecraft_unwrapper_core.transforms import (
    decode_html_entities,
    reconstruct_string_concatenation,
)


class PhaseTwoTests(unittest.TestCase):
    """Validate Phase 2 transformations and limits."""

    def setUp(self) -> None:
        self.configuration = AnalyzerConfig(
            max_depth=6,
            max_output_bytes=1_048_576,
            min_printable_ratio=0.60,
        )

    def test_html_entity_decoding(self) -> None:
        encoded = (
            "Write-Output &quot;"
            "HTML entity test&quot;"
        )

        candidates = decode_html_entities(
            encoded
        )

        self.assertEqual(
            len(candidates),
            1,
        )

        self.assertEqual(
            candidates[0].decoded.decode("utf-8"),
            'Write-Output "HTML entity test"',
        )

    def test_string_concatenation(self) -> None:
        encoded = (
            '"Write" + "-Output" + '
            '" \\"Concatenation test\\""'
        )

        candidates = (
            reconstruct_string_concatenation(
                encoded
            )
        )

        self.assertEqual(
            len(candidates),
            1,
        )

        self.assertEqual(
            candidates[0].decoded.decode("utf-8"),
            'Write-Output "Concatenation test"',
        )

    def test_base64_then_gzip(self) -> None:
        command = (
            b'Write-Output "Gzip pipeline test"'
        )

        compressed = gzip.compress(command)
        encoded = base64.b64encode(
            compressed
        )

        result = analyze_bytes(
            encoded,
            "test-input",
            self.configuration,
        )

        transforms = [
            stage.transform
            for stage in result.stages
        ]

        self.assertIn(
            "base64",
            transforms,
        )

        self.assertIn(
            "gzip",
            transforms,
        )

        self.assertTrue(
            any(
                stage.text
                == command.decode("utf-8")
                for stage in result.stages
            )
        )

    def test_zlib_decompression(self) -> None:
        command = (
            b'Write-Output "Zlib pipeline test"'
        )

        result = analyze_bytes(
            zlib.compress(command),
            "test-input",
            self.configuration,
        )

        self.assertTrue(
            any(
                stage.transform == "zlib"
                and "Zlib pipeline test"
                in stage.text
                for stage in result.stages
            )
        )

    def test_bzip2_decompression(self) -> None:
        command = (
            b'Write-Output "Bzip2 pipeline test"'
        )

        result = analyze_bytes(
            bz2.compress(command),
            "test-input",
            self.configuration,
        )

        self.assertTrue(
            any(
                stage.transform == "bzip2"
                and "Bzip2 pipeline test"
                in stage.text
                for stage in result.stages
            )
        )

    def test_xz_decompression(self) -> None:
        command = (
            b'Write-Output "XZ pipeline test"'
        )

        result = analyze_bytes(
            lzma.compress(
                command,
                format=lzma.FORMAT_XZ,
            ),
            "test-input",
            self.configuration,
        )

        self.assertTrue(
            any(
                stage.transform == "xz"
                and "XZ pipeline test"
                in stage.text
                for stage in result.stages
            )
        )

    def test_compression_limit_is_enforced(
        self,
    ) -> None:
        compressed = gzip.compress(
            b"A" * 10_000
        )

        result = analyze_bytes(
            compressed,
            "test-input",
            AnalyzerConfig(
                max_depth=5,
                max_output_bytes=64,
                min_printable_ratio=0.60,
            ),
        )

        self.assertFalse(
            any(
                stage.transform == "gzip"
                for stage in result.stages
            )
        )

        self.assertTrue(
            any(
                "exceeded" in warning.lower()
                for warning in result.warnings
            )
        )

    def test_malformed_gzip_is_reported(
        self,
    ) -> None:
        malformed = (
            b"\x1f\x8b"
            b"this-is-not-a-valid-gzip-stream"
        )

        result = analyze_bytes(
            malformed,
            "test-input",
            self.configuration,
        )

        self.assertEqual(
            len(result.stages),
            1,
        )

        self.assertTrue(
            any(
                "malformed gzip" in warning.lower()
                for warning in result.warnings
            )
        )


if __name__ == "__main__":
    unittest.main()
