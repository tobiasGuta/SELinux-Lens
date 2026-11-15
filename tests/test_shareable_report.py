"""Privacy and publication checks for reports saved through the desktop UI."""

import contextlib
import io
import json
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from selinux_lens.__main__ import main
from selinux_lens.models import CollectionStatus, Denial, Snapshot
from selinux_lens.report import serialize_shareable_report, write_shareable_report


class ShareableReportTests(unittest.TestCase):
    def setUp(self):
        event = Denial(
            "private-serial", "private-timestamp", "read open", "private_source_context",
            "private_target_context", "file", command="private-process", target="private/path",
            pid="private-pid", permissive=True, raw="private record",
        )
        self.snapshot = Snapshot(
            "Enforcing", (event,), "ausearch", "private diagnostic", CollectionStatus.INCOMPLETE,
        )
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.destination = Path(self.dir.name) / "report.json"

    def test_shareable_report_omits_identifiers_and_preserves_disposition(self):
        text = serialize_shareable_report(self.snapshot)
        obj = json.loads(text)
        self.assertEqual(obj["schema"], "selinux-lens-report/v2")
        self.assertEqual(obj["collection_status"], "incomplete")
        self.assertEqual(obj["events"], [
            {"permissions": "read open", "target_class": "file", "permissive": True},
        ])
        self.assertNotIn("private", text)

    def test_atomic_publication_is_private(self):
        write_shareable_report(self.snapshot, self.destination)
        self.assertEqual(self.destination.read_text(encoding="utf-8"),
                         serialize_shareable_report(self.snapshot))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])

    def test_existing_destination_and_symlink_are_preserved(self):
        original = self.destination.with_name("untouched.txt")
        original.write_text("original", encoding="utf-8")
        self.destination.symlink_to(original)
        with self.assertRaises(FileExistsError):
            write_shareable_report(self.snapshot, self.destination)
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(original.read_text(encoding="utf-8"), "original")
        with self.assertRaises(FileExistsError):
            write_shareable_report(self.snapshot, original)
        self.assertEqual(original.read_text(encoding="utf-8"), "original")

    def test_export_rejects_symlinks_in_parent_and_ancestor_components(self):
        root = self.destination.parent
        actual = root / "actual"
        actual.mkdir()
        nested = actual / "nested"
        nested.mkdir()
        alias = root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        for folder in (alias, alias / "nested"):
            with self.subTest(folder=folder), self.assertRaises(OSError):
                write_shareable_report(self.snapshot, folder / self.destination.name)
        self.assertEqual(list(actual.iterdir()), [nested])
        self.assertEqual(list(nested.iterdir()), [])

    def test_export_keeps_its_open_directory_during_a_rename(self):
        root = self.destination.parent
        selected = root / "selected"
        selected.mkdir()
        moved = root / "moved"
        unrelated = root / "unrelated"
        unrelated.mkdir()

        def rename_directory(_):
            selected.rename(moved)
            selected.symlink_to(unrelated, target_is_directory=True)

        with patch("selinux_lens.report.os.fsync", side_effect=rename_directory):
            write_shareable_report(self.snapshot, selected / self.destination.name)
        self.assertTrue((moved / self.destination.name).is_file())
        self.assertEqual(list(unrelated.iterdir()), [])

    def test_failed_write_leaves_no_output_or_staging(self):
        with patch("selinux_lens.report.os.fsync", side_effect=OSError("storage error")):
            with self.assertRaises(OSError):
                write_shareable_report(self.snapshot, self.destination)
        self.assertEqual(list(self.destination.parent.iterdir()), [])

    def test_concurrent_exports_never_replace_the_winner(self):
        def attempt(_):
            try:
                write_shareable_report(self.snapshot, self.destination)
            except FileExistsError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as writers:
            self.assertEqual(sorted(writers.map(attempt, range(2))), [False, True])
        self.assertEqual(self.destination.read_text(), serialize_shareable_report(self.snapshot))
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])


class EntryPointTests(unittest.TestCase):
    def test_root_gui_launch_is_refused(self):
        stderr = io.StringIO()
        with patch("selinux_lens.__main__.os.geteuid", return_value=0):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["--demo"]), 2)
        self.assertIn("regular desktop account", stderr.getvalue())
