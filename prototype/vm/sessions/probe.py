"""Read real logind and Polkit state for one disposable guest login."""

import json
import os
import sys
import time
from pathlib import Path

from gi.repository import Gio, GLib

ROOT = Path("/run/selinux-lens-sessions")
LOGIN = "org.freedesktop.login1"
LOGIN_PATH = "/org/freedesktop/login1"
POLKIT = "org.freedesktop.PolicyKit1"
POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority"
ACTION = "io.github.tobiasguta.SELinuxLens.read-recent-avcs"


def call(bus, name, path, interface, method, params, result):
    return bus.call_sync(
        name, path, interface, method, params, GLib.VariantType.new(result),
        Gio.DBusCallFlags.NONE, 3_000, None,
    ).unpack()


def session_status(bus):
    path, = call(
        bus, LOGIN, LOGIN_PATH, f"{LOGIN}.Manager", "GetSessionByPID",
        GLib.Variant("(u)", (os.getpid(),)), "(o)",
    )
    props, = call(
        bus, LOGIN, path, "org.freedesktop.DBus.Properties", "GetAll",
        GLib.Variant("(s)", (f"{LOGIN}.Session",)), "(a{sv})",
    )
    subject = ("system-bus-name", {"name": GLib.Variant("s", bus.get_unique_name())})
    (authorized, challenge, _), = call(
        bus, POLKIT, POLKIT_PATH, f"{POLKIT}.Authority", "CheckAuthorization",
        GLib.Variant("((sa{sv})sa{ss}us)", (subject, ACTION, {}, 0, "")), "((bba{ss}))",
    )
    from prototype.audit_reader import SystemAuthorization

    auth = SystemAuthorization(bus)
    peer = auth.peer(bus.get_unique_name())
    assert peer is not None and peer.uid == os.getuid() and peer.pid == os.getpid()
    try:
        binding = auth.binding(peer)
    finally:
        os.close(peer.process_fd)
    return {
        "id": props["Id"], "active": props["Active"], "remote": props["Remote"],
        "seat": props["Seat"][0], "uid": props["User"][0], "class": props["Class"],
        "scope": props["Scope"], "connection": bus.get_unique_name(),
        "authorized": authorized, "challenge": challenge,
        "bound_session": binding.session_id if binding is not None else None,
    }


def run(role):
    assert os.getuid() != 0
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    path = ROOT / (role + ".json")
    temporary = ROOT / (role + ".tmp")
    last = None
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline and not (ROOT / "stop").exists():
        record = session_status(bus)
        if record != last:
            temporary.write_text(json.dumps(record) + "\n", encoding="utf-8")
            temporary.replace(path)
            last = record
        if role == "tty7" and record["active"] and (ROOT / "try-auth").exists() and (
            ROOT / "lab-admin-password"
        ).exists():
            from authorization import run as exercise_polkit

            exercise_polkit(bus)
        time.sleep(0.25)


if __name__ == "__main__":
    sys.path.insert(0, "/mnt/code")
    name = sys.argv[1]
    role = os.ttyname(0).removeprefix("/dev/") if name == "login" else name
    if role not in {"tty7", "tty8", "tty9"}:
        raise SystemExit("Expected an isolated guest login")
    run(role)
