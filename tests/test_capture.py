"""Exercise real pipes and process cleanup with synthetic child output."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Event, Thread
from time import monotonic

from selinux_lens.audit import (
    CaptureLimitReached,
    CollectionCancelled,
    _run,
    load_recent,
)


class BoundedCaptureTests(unittest.TestCase):
    def run_child(self, code, *, timeout=2, cancel=None, args=()):
        return _run(
            [sys.executable, "-c", code, *args],
            timeout=timeout,
            output_limit=131_072,
            error_limit=16_384,
            cancel=cancel,
        )

    def test_drains_both_pipes_and_collects_exit_code_at_limits(self):
        result = self.run_child(
            "import sys; sys.stderr.buffer.write(b'e' * 16384); "
            "sys.stdout.buffer.write(b'o' * 131072); sys.exit(3)"
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"o" * 131_072)
        self.assertEqual(result.stderr, b"e" * 16_384)

    def test_stdout_and_stderr_floods_hit_independent_limits(self):
        for fd in (1, 2):
            with self.subTest(fd=fd), self.assertRaises(CaptureLimitReached):
                self.run_child(f"import os; block = b'x' * 65536\nwhile True: os.write({fd}, block)")

    def test_timeout_reaps_child_with_open_or_closed_pipes(self):
        for close_pipes in ("", "os.close(1); os.close(2); "):
            with self.subTest(close_pipes=close_pipes), tempfile.TemporaryDirectory() as tmp:
                pid_file = Path(tmp) / "pid"
                code = (
                    "import os, sys, time; "
                    "from pathlib import Path; "
                    "Path(sys.argv[1]).write_text(str(os.getpid())); "
                    f"{close_pipes}time.sleep(60)"
                )
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.run_child(code, timeout=0.5, args=(str(pid_file),))
                with self.assertRaises(ChildProcessError):
                    os.waitpid(int(pid_file.read_text()), os.WNOHANG)

    def test_active_cancellation_interrupts_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "pid"
            cancel = Event()
            done = Event()

            def cancel_on_start():
                while not done.wait(0.01):
                    if pid_file.exists() and pid_file.stat().st_size:
                        cancel.set()
                        return

            trigger = Thread(target=cancel_on_start)
            trigger.start()
            start = monotonic()
            try:
                with self.assertRaises(CollectionCancelled):
                    self.run_child(
                        "import os, sys, time; from pathlib import Path; "
                        "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)",
                        timeout=5, cancel=cancel, args=(str(pid_file),),
                    )
                self.assertLess(monotonic() - start, 3)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(int(pid_file.read_text()), os.WNOHANG)
            finally:
                done.set()
                trigger.join()

    def test_already_cancelled_query_reports_cancellation(self):
        cancel = Event()
        cancel.set()
        self.assertEqual(load_recent(cancel=cancel).notice, "Audit query cancelled.")

    def test_collection_translates_timeout_and_cap_to_distinct_notices(self):
        for problem, notice in (
            (subprocess.TimeoutExpired(["ausearch"], 12), "timed out"),
            (CaptureLimitReached(), "safety limit"),
        ):
            def runner(command, *, failure=problem, **_kwargs):
                if command == ["/usr/sbin/getenforce"]:
                    return subprocess.CompletedProcess(command, 0, b"Enforcing", b"")
                raise failure

            with self.subTest(problem=problem):
                snapshot = load_recent(runner=runner)
                self.assertEqual(snapshot.mode, "Enforcing")
                self.assertEqual(snapshot.events, ())
                self.assertIn(notice, snapshot.notice)
