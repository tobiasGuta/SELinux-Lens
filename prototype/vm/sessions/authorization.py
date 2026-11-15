"""Exercise the guest Polkit action with the standard text agent and real PAM."""

import json
import os
import pty
import re
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

from gi.repository import Gio, GLib

AUTHORITY = "org.freedesktop.PolicyKit1"
INTERFACE = AUTHORITY + ".Authority"
PATH = "/org/freedesktop/PolicyKit1/Authority"
ACTION = "io.github.tobiasguta.SELinuxLens.read-recent-avcs"
ROOT = Path("/run/selinux-lens-sessions")


def rpc(bus, method, args, sig, timeout):
    return bus.call_sync(
        AUTHORITY, PATH, INTERFACE, method, args, GLib.VariantType.new(sig),
        Gio.DBusCallFlags.NONE, timeout, None,
    ).unpack()


class Agent:
    def __enter__(self):
        self.master, slave = pty.openpty()
        ready, notify = os.pipe()
        try:
            self.agent = subprocess.Popen(
                [sys.executable, "-c", "import os, sys; os.login_tty(0); os.execv(sys.argv[1], sys.argv[1:])",
                 "/usr/bin/pkttyagent", "--process", str(os.getpid()), "--notify-fd", str(notify)],
                stdin=slave, stdout=slave, stderr=slave, pass_fds=(notify,),
                env={**os.environ, "LC_ALL": "C"},
            )
        except BaseException:
            os.close(ready)
            os.close(self.master)
            raise
        finally:
            os.close(slave)
            os.close(notify)
        try:
            if not select.select([ready], [], [], 6)[0] or self.agent.poll() is not None:
                raise RuntimeError("Polkit text agent did not register")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        finally:
            os.close(ready)
        return self

    def __exit__(self, *_):
        if self.agent.poll() is None:
            self.agent.terminate()
        try:
            self.agent.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.agent.kill()
            self.agent.wait()
        os.close(self.master)

    def wait_for_password(self, finished):
        transcript = b""
        selected = False
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not finished.is_set():
            if select.select([self.master], [], [], 0.1)[0]:
                transcript = (transcript + os.read(self.master, 2048))[-8192:]
                if not selected and b"authenticate as" in transcript.lower():
                    choice = re.search(rb"(?m)^\s*(\d+)\. .*lens-admin", transcript)
                    if choice:
                        os.write(self.master, choice[1] + b"\n")
                        selected = True
                if b"password:" in transcript.lower():
                    return
        raise RuntimeError("No live Polkit password prompt")


def check(bus, agent, *, mode, password, observer):
    subject = ("system-bus-name", {"name": GLib.Variant("s", bus.get_unique_name())})
    check_id = uuid4().hex
    outcome = []
    finished = threading.Event()

    def begin():
        try:
            (granted, _, details), = rpc(
                bus, "CheckAuthorization",
                GLib.Variant("((sa{sv})sa{ss}us)", (subject, ACTION, {}, 1, check_id)),
                "((bba{ss}))", 2_500 if mode == "timeout" else 10_000,
            )
            outcome.append({
                "authorized": granted,
                "temporary": bool(details.get("polkit.temporary_authorization_id")),
                "dismissed": bool(details.get("polkit.dismissed")),
            })
        except GLib.Error as error:
            outcome.append({
                "error": Gio.DBusError.get_remote_error(error) or error.domain,
                "timed_out": error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.TIMED_OUT),
            })
        finally:
            finished.set()

    worker = threading.Thread(target=begin)
    worker.start()
    try:
        agent.wait_for_password(finished)
        if mode == "cancel":
            rpc(bus, "CancelCheckAuthorization", GLib.Variant("(s)", (check_id,)), "()", 2_000)
        elif mode == "approve":
            os.write(agent.master, password.strip() + b"\n")
        elif mode == "dismiss":
            os.write(agent.master, b"\x03")
        elif mode == "disconnect":
            sender = bus.get_unique_name()
            bus.close_sync(None)
            reply = observer.call_sync(
                "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "NameHasOwner", GLib.Variant("(s)", (sender,)), GLib.VariantType.new("(b)"),
                Gio.DBusCallFlags.NONE, 2_000, None,
            )
            assert reply.unpack() == (False,)
    finally:
        worker.join()
    answer = outcome[0]
    if mode == "approve":
        assert answer == {"authorized": True, "temporary": False, "dismissed": False}, answer
    else:
        assert not answer.get("authorized"), answer
    if mode == "timeout":
        assert answer.get("timed_out"), answer
        rpc(bus, "CancelCheckAuthorization", GLib.Variant("(s)", (check_id,)), "()", 2_000)
    return answer


def run(bus):
    secret = ROOT / "lab-admin-password"
    password = secret.read_bytes()
    secret.unlink()
    report = {}
    try:
        try:
            rpc(bus, "CheckAuthorization", GLib.Variant("(s)", (ACTION,)), "((bba{ss}))", 2_000)
        except GLib.Error as error:
            assert Gio.DBusError.get_remote_error(error) == "org.freedesktop.DBus.Error.InvalidArgs"
            report["malformed_policy_call"] = "rejected"
        else:
            raise AssertionError("Polkit accepted a malformed signature")
        for mode in ("approve", "cancel", "timeout", "dismiss", "disconnect"):
            if mode == "disconnect":
                caller = Gio.DBusConnection.new_for_address_sync(
                    Gio.dbus_address_get_for_bus_sync(Gio.BusType.SYSTEM, None),
                    Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
                    | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
                    None, None,
                )
            else:
                caller = bus
            with Agent() as agent:
                report[mode] = check(caller, agent, mode=mode, password=password, observer=bus)
            if mode == "approve":
                subject = ("system-bus-name", {"name": GLib.Variant("s", bus.get_unique_name())})
                (authorized, challenge, _), = rpc(
                    bus, "CheckAuthorization",
                    GLib.Variant("((sa{sv})sa{ss}us)", (subject, ACTION, {}, 0, "")),
                    "((bba{ss}))", 2_000,
                )
                assert not authorized and challenge
                report["authorization_reused"] = False
    except Exception as failure:
        report["error"] = str(failure)
    result = ROOT / "authentication.json"
    temporary = result.with_suffix(".tmp")
    temporary.write_text(json.dumps(report), encoding="utf-8")
    temporary.replace(result)
