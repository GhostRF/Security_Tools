"""Tests for optional embedded encoded-fragment scanning."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIRECTORY))

from tradecraft_unwrapper_core.embedded import scan_embedded_fragments


class EmbeddedFragmentTests(unittest.TestCase):
    """Validate conservative embedded Base64 and hexadecimal discovery."""

    def test_embedded_base64_fragment_is_reported(self) -> None:
        text = (
            '$s = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp'
            'LkRvd25sb2FkU3RyaW5nKCJodHRwOi8vZXZpbC94Iik="'
        )

        candidates = scan_embedded_fragments(text)

        self.assertTrue(
            any(
                candidate.kind == "embedded-base64"
                and "New-Object Net.WebClient" in candidate.decoded_preview
                for candidate in candidates
            )
        )

    def test_embedded_hex_fragment_is_reported(self) -> None:
        text = "prefix 636d642e657865202f632077686f616d69 suffix"

        candidates = scan_embedded_fragments(text)

        self.assertTrue(
            any(
                candidate.kind == "embedded-hex"
                and "cmd.exe /c whoami" in candidate.decoded_preview
                for candidate in candidates
            )
        )

    def test_benign_text_does_not_create_candidates(self) -> None:
        text = "This is normal analyst text with no embedded encoded fragment."

        candidates = scan_embedded_fragments(text)

        self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()
