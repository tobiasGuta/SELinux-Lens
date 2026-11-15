"""Correlation and parser boundary tests using fictional audit records."""

import unittest
from pathlib import Path

from selinux_lens.audit import MAX_LINE_CHARS, parse_ausearch
from selinux_lens.explain import interpret
from selinux_lens.models import Snapshot
from selinux_lens.report import build_report, serialize_report

FIXTURE = (Path(__file__).parent / "fixtures" / "correlation.txt").read_text(encoding="utf-8")
AVC_LINE = FIXTURE.splitlines()[2]
IDENTITY = "node=alpha type={kind} msg=audit(1700000000.123:42): "


class CorrelationTests(unittest.TestCase):
    def test_group_uses_capture_node_epoch_and_serial_and_preserves_line_numbers(self):
        user_avc, avc = parse_ausearch(FIXTURE)
        self.assertEqual(avc.timestamp_utc, "2023-11-14T22:13:20+00:00")
        evidence = avc.evidence
        self.assertEqual(
            (evidence.node, evidence.epoch, evidence.line_number), ("alpha", "1700000000.123", 3)
        )
        self.assertEqual(
            [(r.kind, r.line_number) for r in evidence.related],
            [("SYSCALL", 4), ("PATH", 5), ("PATH", 7), ("PROCTITLE", 9)],
        )
        self.assertEqual({r.path_item for r in evidence.related if r.kind == "PATH"}, {0, 2})
        self.assertEqual(evidence.expected_paths, 3)
        self.assertEqual(avc.target, "")
        self.assertEqual(avc.command, "demo-worker")
        self.assertTrue(user_avc.permissive)
        self.assertEqual(user_avc.pid, "16")
        self.assertIn("would deny", interpret(user_avc).observed)
        self.assertEqual([r.kind for r in user_avc.evidence.related], ["PATH"])
        self.assertIsNone(user_avc.evidence.expected_paths)

    def test_attachment_stays_within_one_capture_even_with_reused_identity(self):
        avc, = parse_ausearch(AVC_LINE)
        unrelated = IDENTITY.format(kind="PATH") + 'item=0 name="/fictional/other-capture"'
        self.assertEqual(parse_ausearch(unrelated), ())
        self.assertEqual(avc.evidence.related, ())

    def test_conflicting_syscall_counts_leave_expected_path_count_unknown(self):
        lines = [AVC_LINE]
        for count in (0, 2):
            lines.append(IDENTITY.format(kind="SYSCALL") + f"arch=c000003e syscall=257 items={count}")
        avc, = parse_ausearch("\n".join(lines))
        self.assertEqual(len(avc.evidence.related), 2)
        self.assertIsNone(avc.evidence.expected_paths)

    def test_embedded_markers_and_malformed_headers_are_ignored(self):
        noise = [
            f'type=SYSCALL msg=audit(1700000000.123:42): comm="{AVC_LINE}"',
            f'message="{AVC_LINE}"',
            AVC_LINE.replace("1700000000.123", "9999999999999999999"),
            AVC_LINE.replace("msg=audit(", "message=audit("),
            AVC_LINE.replace("avc:  denied", 'detail="avc: denied"'),
        ]
        self.assertEqual(parse_ausearch("\n".join(noise)), ())

    def test_field_tokens_inside_quotes_and_enrichment_do_not_change_disposition(self):
        line = AVC_LINE.replace(
            'comm="demo-worker" tclass=file permissive=0',
            'comm="fake permissive=0" name="tabs\tand\u202etext" permissive=1\x1dPERMISSIVE=0',
        )
        avc, = parse_ausearch(line)
        self.assertTrue(avc.permissive)
        self.assertEqual(avc.command, "fake permissive=0")
        self.assertEqual(avc.target, "tabs\tand\u202etext")
        self.assertEqual(avc.raw, line)

    def test_conflicting_field_and_broken_quoted_value_are_unknown(self):
        for line in (
            AVC_LINE + " permissive=1",
            AVC_LINE.replace('comm="demo-worker"', 'comm="unterminated'),
        ):
            with self.subTest(line=line):
                avc, = parse_ausearch(line)
                self.assertIsNone(avc.permissive)

    def test_control_characters_do_not_form_line_boundaries_and_long_lines_are_skipped(self):
        wrong = IDENTITY.format(kind="PATH") + 'item=0 name="/fictional/injected"'
        separate = IDENTITY.format(kind="PATH") + 'item=1 name="' + ('x' * MAX_LINE_CHARS) + '"'
        avcs = parse_ausearch(AVC_LINE + "\u2028" + wrong + "\n" + separate + "\n" + AVC_LINE)
        self.assertEqual([avc.evidence.line_number for avc in avcs], [1, 3])
        self.assertTrue(all(not avc.evidence.related for avc in avcs))

    def test_v1_export_keeps_companion_records_out(self):
        _, grouped = parse_ausearch(FIXTURE)
        single, = parse_ausearch(AVC_LINE)
        grouped_report = Snapshot("Enforcing", (grouped,), "ausearch")
        single_report = Snapshot("Enforcing", (single,), "ausearch")
        self.assertEqual(build_report(grouped_report)["events"], build_report(single_report)["events"])
        exported = serialize_report(grouped_report)
        self.assertNotIn("/fictional/first", exported)
        self.assertNotIn("PROCTITLE", exported)
