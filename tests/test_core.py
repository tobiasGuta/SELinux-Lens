"""Tests run with stdlib only: no GTK, SELinux policy or root required."""

from __future__ import annotations

import json
import subprocess
import unittest

from selinux_lens.audit import MAX_EVENTS, load_recent, parse_ausearch, selinux_mode
from selinux_lens.demo import demo_snapshot
from selinux_lens.explain import interpret
from selinux_lens.models import CollectionStatus, Snapshot
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
        if args == ["/usr/sbin/getenforce"]:
            return subprocess.CompletedProcess(args, 0, stdout=b"Enforcing\n", stderr=b"")
        if args == ["/usr/sbin/ausearch", "--input-logs", "-m", "AVC,USER_AVC", "-ts", "recent"]:
            return subprocess.CompletedProcess(args, 0, stdout=AVC.encode(), stderr=b"")
        raise AssertionError(f"Unexpected command: {args}")

    def test_runs_fixed_commands_and_loads_event(self):
        snap = load_recent(runner=self.fake_run)
        self.assertEqual(snap.mode, "Enforcing")
        self.assertEqual(len(snap.events), 1)
        self.assertEqual(snap.source, "ausearch")

    def load_result(self, returncode, stdout=b"", stderr=b""):
        def runner(args, **kwargs):
            if args[0] == "/usr/sbin/getenforce":
                return self.fake_run(args, **kwargs)
            return subprocess.CompletedProcess(args, returncode, stdout, stderr)
        return load_recent(runner=runner)

    def test_permission_denied_is_not_silent(self):
        snap = self.load_result(1, stderr=b"Permission denied")
        self.assertEqual(snap.events, ())
        self.assertEqual(snap.status, CollectionStatus.PERMISSION_DENIED)
        self.assertIn("access was denied", snap.notice)

    def test_ausearch_no_matches_is_distinct_from_a_failed_query(self):
        empty = self.load_result(1, stderr=b"<no matches>\n")
        self.assertEqual(empty.status, CollectionStatus.NO_MATCHES)
        self.assertIn("No AVC denials", empty.notice)
        failed = self.load_result(1)
        self.assertEqual(failed.status, CollectionStatus.FAILED)
        self.assertIn("query failed", failed.notice)
        self.assertIn(
            "query failed", self.load_result(1, stderr=b"Read error\n<no matches>\n").notice
        )

    def test_warning_or_unparseable_output_is_not_an_empty_success(self):
        for snap in (
            self.load_result(0, stderr=b"configuration warning"),
            self.load_result(0, stdout=b"unsupported format"),
        ):
            self.assertEqual(snap.status, CollectionStatus.INCOMPLETE)
            self.assertEqual(snap.events, ())
        partial = self.load_result(0, stdout=AVC.encode(), stderr=b"configuration warning")
        self.assertEqual(partial.status, CollectionStatus.INCOMPLETE)
        self.assertEqual(len(partial.events), 1)
        self.assertNotIn("configuration", partial.notice)

    def test_record_limit_retains_only_complete_denial_records(self):
        text = "\n".join(AVC for _ in range(MAX_EVENTS + 1)).encode()
        snapshot = self.load_result(0, stdout=text)
        self.assertEqual(snapshot.status, CollectionStatus.OUTPUT_LIMIT)
        self.assertEqual(len(snapshot.events), MAX_EVENTS)

    def test_failure_does_not_publish_partial_output_or_raw_diagnostics(self):
        snap = self.load_result(2, stdout=AVC.encode(), stderr=b"/private/diagnostic")
        self.assertEqual(snap.events, ())
        self.assertEqual(snap.notice, "Audit query failed (exit 2).")
        self.assertNotIn("/private", serialize_report(snap))

    def test_invalid_utf8_is_replaced_without_hiding_event(self):
        payload = AVC.encode().replace(b"secret.txt", b"example-\xff.txt")
        event, = self.load_result(0, stdout=payload).events
        self.assertEqual(event.target, "example-\ufffd.txt")

    def test_missing_ausearch(self):
        def runner(args, **kwargs):
            if args[0] == "/usr/sbin/getenforce":
                return self.fake_run(args, **kwargs)
            raise FileNotFoundError()
        snap = load_recent(runner=runner)
        self.assertIn("unavailable", snap.notice)

    def test_enforcement_unknown(self):
        def runner(*_args, **_kwargs):
            raise FileNotFoundError()
        self.assertEqual(selinux_mode(runner=runner), "Unknown")


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
