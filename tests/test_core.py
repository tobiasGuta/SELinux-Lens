"""Tests run with stdlib only: no GTK, SELinux policy or root required."""

from __future__ import annotations

import json
import subprocess
import unittest

from selinux_lens.audit import MAX_OUTPUT_BYTES, load_recent, parse_ausearch, selinux_mode
from selinux_lens.demo import demo_snapshot
from selinux_lens.explain import interpret
from selinux_lens.models import Snapshot
from selinux_lens.report import build_report, serialize_report


AVC = (
    'type=AVC msg=audit(1763150400.123:42): avc: denied { read open } for '
    'pid=555 comm="httpd" name="secret.txt" '
    'scontext=system_u:system_r:httpd_t:s0 '
    'tcontext=unconfined_u:object_r:user_home_t:s0 '
    'tclass=file permissive=0'
)


class ParseTests(unittest.TestCase):
    def test_extracts_realistic_avc(self):
        event, = parse_ausearch(AVC)
        self.assertEqual(event.event_id, "42")
        self.assertEqual(event.permissions, "read open")
        self.assertEqual(event.source_type, "httpd_t")
        self.assertEqual(event.target_type, "user_home_t")
        self.assertEqual(event.target, "secret.txt")
        self.assertEqual(event.command, "httpd")
        self.assertFalse(event.permissive)
        self.assertIn("+00:00", event.timestamp_utc)

    def test_ignores_other_records_and_broken_lines(self):
        noise = "type=SYSCALL msg=audit(1763150400.123:42): arch=c000003e"
        self.assertEqual(len(parse_ausearch(noise + "\n" + AVC + "\nnope")), 1)

    def test_permissive_is_not_described_as_blocked(self):
        text = AVC.replace("type=AVC", "type=USER_AVC").replace(
            "permissive=0", "permissive=1"
        )
        event, = parse_ausearch(text)
        self.assertTrue(event.permissive)
        self.assertIn("would deny", interpret(event).observed)

    def test_limit_and_order(self):
        newer = AVC.replace("1763150400.123:42", "1763150500.123:43")
        events = parse_ausearch(AVC + "\n" + newer, limit=1)
        self.assertEqual([event.event_id for event in events], ["43"])

    def test_empty_and_invalid_limit(self):
        self.assertEqual(parse_ausearch(""), ())
        self.assertEqual(parse_ausearch(AVC, limit=0), ())

    def test_demo_is_labeled_fictional(self):
        snap = demo_snapshot()
        self.assertEqual(snap.source, "demo")
        self.assertEqual(len(snap.events), 3)
        self.assertIn("fictional", snap.notice.lower())


class CollectionTests(unittest.TestCase):
    @staticmethod
    def fake_run(args, **_kwargs):
        if args == ["getenforce"]:
            return subprocess.CompletedProcess(args, 0, stdout="Enforcing\n", stderr="")
        if args == ["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent"]:
            return subprocess.CompletedProcess(args, 0, stdout=AVC, stderr="")
        raise AssertionError(f"Unexpected command: {args}")

    def test_runs_fixed_commands_and_loads_event(self):
        snap = load_recent(runner=self.fake_run)
        self.assertEqual(snap.mode, "Enforcing")
        self.assertEqual(len(snap.events), 1)
        self.assertEqual(snap.source, "ausearch")

    def test_permission_denied_is_not_silent(self):
        def runner(args, **_kwargs):
            if args[0] == "getenforce":
                return subprocess.CompletedProcess(args, 0, "Enforcing", "")
            return subprocess.CompletedProcess(args, 1, "", "Permission denied")
        snap = load_recent(runner=runner)
        self.assertEqual(snap.events, ())
        self.assertIn("access was denied", snap.notice)

    def test_missing_ausearch(self):
        def runner(args, **_kwargs):
            if args[0] == "getenforce":
                return subprocess.CompletedProcess(args, 0, "Enforcing", "")
            raise FileNotFoundError()
        snap = load_recent(runner=runner)
        self.assertIn("unavailable", snap.notice)

    def test_enforcement_unknown(self):
        def runner(*_args, **_kwargs):
            raise FileNotFoundError()
        self.assertEqual(selinux_mode(runner=runner), "Unknown")

    def test_output_limit(self):
        def runner(args, **_kwargs):
            if args[0] == "getenforce":
                return subprocess.CompletedProcess(args, 0, "Enforcing", "")
            return subprocess.CompletedProcess(args, 0, "x" * (MAX_OUTPUT_BYTES + 1), "")
        snap = load_recent(runner=runner)
        self.assertIn("safety limit", snap.notice)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = Snapshot("Enforcing", parse_ausearch(AVC), "ausearch")

    def test_redacts_name_and_does_not_export_raw_line(self):
        obj = json.loads(serialize_report(self.snapshot))
        self.assertEqual(obj["schema"], "selinux-lens-report/v1")
        self.assertEqual(obj["events"][0]["target"], "[redacted]")
        self.assertNotIn("raw", obj["events"][0])
        self.assertNotIn("secret.txt", serialize_report(self.snapshot))

    def test_explicit_paths_option(self):
        obj = build_report(self.snapshot, include_paths=True)
        self.assertEqual(obj["events"][0]["target"], "secret.txt")
        self.assertFalse(obj["redacted_target_paths"])

    def test_no_auto_policy_fixes_in_explanations(self):
        self.assertNotIn("audit2allow", serialize_report(self.snapshot).lower())
        self.assertIn("possible_explanations", build_report(self.snapshot)["events"][0])


if __name__ == "__main__":
    unittest.main()
