"""Exercise the uninstalled reader on a private D-Bus with synthetic evidence."""

import os
import subprocess
import threading
import unittest
from unittest.mock import patch

from gi.repository import Gio, GLib

from prototype import audit_reader as reader


def connection():
    return Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )


class Authorization:
    def __init__(self, conn):
        self.system = reader.SystemAuthorization(conn)
        self.calls = []
        self.approve = True
        self.eligible_calls = 0
        self.expire_after = 99

    def peer(self, name):
        self.calls.append("peer")
        return self.system.peer(name)

    def eligible(self, peer):
        self.eligible_calls += 1
        return peer.alive() and self.eligible_calls <= self.expire_after

    def authorize(self, peer, cancel):
        self.calls.append("authorize")
        return self.approve


class PrivateBusTests(unittest.TestCase):
    def setUp(self):
        self.server = connection()
        self.addCleanup(self.server.close_sync, None)
        self.client = connection()
        self.addCleanup(self.client.close_sync, None)
        self.auth = Authorization(self.server)

        def collect(cancel):
            self.auth.calls.append("collect")
            return "ok", [("1700000000.123", "42", "read", "", "", "file", 2)]

        self.service = reader.AuditReader(self.server, self.auth, collect)
        self.addCleanup(self.service.close)

    def request(self, *, interactive=True, params=None, client=None):
        client = self.client if client is None else client
        loop = GLib.MainLoop()
        results = []
        failures = []
        flags = (
            Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION
            if interactive else Gio.DBusCallFlags.NONE
        )

        def call():
            try:
                reply = client.call_sync(
                    self.server.get_unique_name(), reader.OBJECT_PATH, reader.INTERFACE,
                    "GetRecentAvcs", params or GLib.Variant("()", ()),
                    GLib.VariantType.new(reader.RETURN_TYPE), flags, 3_000, None,
                )
                results.append(reply.unpack())
            except GLib.Error as exc:
                failures.append(exc)
            finally:
                GLib.idle_add(loop.quit)

        worker = threading.Thread(target=call)
        worker.start()
        loop.run()
        worker.join()
        if failures:
            raise failures[0]
        return results[0]

    def test_connection_pins_real_private_bus_peer(self):
        peer = self.auth.system.peer(self.client.get_unique_name())
        try:
            self.assertEqual((peer.uid, peer.pid), (os.getuid(), os.getpid()))
            self.assertTrue(peer.alive())
        finally:
            os.close(peer.process_fd)

    def test_missing_interactive_flag_never_checks_or_collects(self):
        self.assertEqual(self.request(interactive=False), ("denied", []))
        self.assertEqual(self.auth.calls, [])

    def test_bad_signature_never_checks_or_collects(self):
        with self.assertRaises(GLib.Error):
            self.request(params=GLib.Variant("(s)", ("unexpected",)))
        self.assertEqual(self.auth.calls, [])

    def test_authorized_read_and_repeat_rate_limit(self):
        status, records = self.request()
        self.assertEqual((status, records[0][-1]), ("ok", 2))
        self.assertEqual(self.request(), ("rate_limited", []))
        self.assertEqual(self.auth.calls, ["peer", "authorize", "collect"])

    def test_denied_peer_never_collects(self):
        self.auth.approve = False
        self.assertEqual(self.request(), ("denied", []))
        self.assertEqual(self.auth.calls, ["peer", "authorize"])

    def test_ineligible_peer_never_prompts_or_collects(self):
        self.auth.expire_after = 0
        self.assertEqual(self.request(), ("denied", []))
        self.assertEqual(self.auth.calls, ["peer"])

    def test_parallel_request_is_busy_and_disconnect_cancels_authorization(self):
        second_client = connection()
        self.addCleanup(second_client.close_sync, None)
        abandoned_client = connection()
        entered = threading.Event()
        cancelled = threading.Event()

        def authorize(_peer, cancel):
            entered.set()
            for _ in range(200):
                if cancel.is_cancelled():
                    cancelled.set()
                    return False
                threading.Event().wait(0.01)
            return False

        def abandoned_call():
            try:
                abandoned_client.call_sync(
                    self.server.get_unique_name(), reader.OBJECT_PATH, reader.INTERFACE,
                    "GetRecentAvcs", GLib.Variant("()", ()),
                    GLib.VariantType.new(reader.RETURN_TYPE),
                    Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, 3_000, None,
                )
            except GLib.Error:
                pass

        def iterate_until(event):
            loop = GLib.MainLoop()
            ticks = 0

            def check():
                nonlocal ticks
                ticks += 1
                if event.is_set() or ticks == 200:
                    loop.quit()
                    return GLib.SOURCE_REMOVE
                return GLib.SOURCE_CONTINUE

            GLib.timeout_add(5, check)
            loop.run()
            self.assertTrue(event.is_set())

        worker = threading.Thread(target=abandoned_call)
        with patch.object(self.auth, "authorize", side_effect=authorize):
            worker.start()
            try:
                iterate_until(entered)
                self.assertEqual(self.request(client=second_client), ("busy", []))
            finally:
                abandoned_client.close_sync(None)
                worker.join()
            iterate_until(cancelled)
        self.assertNotIn("collect", self.auth.calls)

    def test_session_changes_discard_results(self):
        self.auth.expire_after = 2
        self.assertEqual(self.request(), ("cancelled", []))
        self.assertEqual(self.auth.calls, ["peer", "authorize", "collect"])

    def test_authorization_failure_discards_results(self):
        with patch.object(self.auth, "authorize", side_effect=GLib.Error("test authority absent")):
            self.assertEqual(self.request(), ("unavailable", []))
        self.assertEqual(self.auth.calls, ["peer"])


class PolicyAndProjectionTests(unittest.TestCase):
    def test_policy_request_is_bound_to_connection_and_explicitly_cancelled(self):
        auth = reader.SystemAuthorization(None)
        peer = reader.Peer(":1.23", 1000, 5, -1)
        with patch.object(
            auth, "_call", side_effect=[GLib.Error("simulated authorization deadline"), ()]
        ) as send, self.assertRaises(GLib.Error):
            auth.authorize(peer, Gio.Cancellable())
        first, second = [call.args for call in send.call_args_list]
        subject, action, details, flags, check_id = first[4].unpack()
        self.assertEqual(subject, ("system-bus-name", {"name": ":1.23"}))
        self.assertEqual((action, details, flags), (reader.ACTION, {}, 1))
        self.assertTrue(check_id)
        self.assertEqual((second[3], second[4].unpack()), ("CancelCheckAuthorization", (check_id,)))

    def test_fixed_raw_collection_projects_only_supported_evidence(self):
        output = (
            b'type=AVC msg=audit(1700000000.123:42): avc: denied { read } for '
            b'comm="private-process" name="private-path" pid=123 '
            b'scontext=system_u:system_r:httpd_t:s0 tcontext=bad/field tclass=file permissive=1\n'
        )
        with patch.object(reader.audit, "_run", return_value=subprocess.CompletedProcess([], 0, output, b"")) as run:
            status, records = reader._collect(threading.Event())
        self.assertEqual(status, "ok")
        self.assertEqual(records, [("1700000000.123", "42", "read", "system_u:system_r:httpd_t:s0", "", "file", 2)])
        self.assertEqual(run.call_args.args[0][0:2], ["/usr/sbin/ausearch", "--input-logs"])
        self.assertEqual(run.call_args.kwargs["timeout"], 12)
        self.assertEqual(run.call_args.kwargs["output_limit"], 2_000_000)
        self.assertEqual(run.call_args.kwargs["error_limit"], 16_384)

    def test_collection_reports_distinct_empty_and_warnings(self):
        for result, expected in (
            (subprocess.CompletedProcess([], 1, b"", b"<no matches>\n"), "empty"),
            (subprocess.CompletedProcess([], 1, b"", b"Permission denied"), "unavailable"),
            (subprocess.CompletedProcess([], 0, b"type=malformed", b""), "incomplete"),
        ):
            with self.subTest(expected=expected), patch.object(reader.audit, "_run", return_value=result):
                self.assertEqual(reader._collect(threading.Event()), (expected, []))

    def test_reply_limit_is_enforced(self):
        record = ("1.0", "2", "read", "s" * 4096, "t" * 4096, "file", 0)
        reply = reader._reply("ok", [record] * 200)
        status, output = reply.unpack()
        self.assertEqual(status, "capped")
        self.assertGreater(len(output), 0)
        self.assertLessEqual(reply.get_size(), reader.MAX_REPLY_BYTES)
