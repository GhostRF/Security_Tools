import json
import tempfile
import unittest
from pathlib import Path
from datetime import timezone

import attack_correlator as ac


class TestAttackCorrelator(unittest.TestCase):

    def test_parse_time_iso_z(self):
        dt = ac.parse_time("2026-05-21T08:00:00Z")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 5)
        self.assertEqual(dt.day, 21)

    def test_normalize_sysmon_process_event(self):
        record = {
            "UtcTime": "2026-05-21T08:00:00Z",
            "EventID": "1",
            "Computer": "host1",
            "User": "alice",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA",
        }

        event = ac.normalize_record(record, "sample_sysmon.jsonl")

        self.assertEqual(event.event_category, "process")
        self.assertEqual(event.host, "host1")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertIn("-enc", event.command_line)

    def test_powershell_detection_rule_matches(self):
        event = ac.normalize_record(
            {
                "UtcTime": "2026-05-21T08:00:00Z",
                "EventID": "1",
                "Computer": "host1",
                "User": "alice",
                "Image": "powershell.exe",
                "CommandLine": "powershell.exe -encodedcommand AAAA",
            },
            "sample_sysmon.jsonl",
        )

        ac.apply_detections([event])

        technique_ids = {d["technique_id"] for d in event.detections}
        self.assertIn("T1059.001", technique_ids)

    def test_dga_rule_excludes_local_domain(self):
        event = ac.normalize_record(
            {
                "ts": 1780000000.0,
                "query": "abcdefghijklmnopqrst.local",
                "id.orig_h": "192.168.1.10",
            },
            "dns.log",
        )

        ac.apply_detections([event])

        technique_ids = {d["technique_id"] for d in event.detections}
        self.assertNotIn("T1568.002", technique_ids)

    def test_dga_rule_matches_long_external_domain(self):
        event = ac.normalize_record(
            {
                "ts": 1780000000.0,
                "query": "abcdefghijklmnopqrst.example.com",
                "id.orig_h": "192.168.1.10",
            },
            "dns.log",
        )

        ac.apply_detections([event])

        technique_ids = {d["technique_id"] for d in event.detections}
        self.assertIn("T1568.002", technique_ids)

    def test_correlate_groups_related_events(self):
        events = [
            ac.normalize_record(
                {
                    "UtcTime": "2026-05-21T08:00:00Z",
                    "EventID": "1",
                    "Computer": "host1",
                    "User": "alice",
                    "Image": "powershell.exe",
                    "CommandLine": "powershell.exe -enc AAAA",
                },
                "sample_sysmon.jsonl",
            ),
            ac.normalize_record(
                {
                    "UtcTime": "2026-05-21T08:05:00Z",
                    "EventID": "1",
                    "Computer": "host1",
                    "User": "alice",
                    "Image": "cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                },
                "sample_sysmon.jsonl",
            ),
        ]

        ac.apply_detections(events)
        chains = ac.correlate(events, window_minutes=60)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["host"], "host1")
        self.assertEqual(chains[0]["user"], "alice")
        self.assertGreaterEqual(chains[0]["event_count"], 2)

    def test_read_jsonl_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(
                json.dumps({"EventID": "1", "Image": "cmd.exe", "CommandLine": "cmd.exe /c whoami"}) + "\n"
                + json.dumps({"EventID": "1", "Image": "powershell.exe", "CommandLine": "powershell.exe -enc AAAA"}) + "\n"
            )

            records = list(ac.read_json_file(path))

        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
