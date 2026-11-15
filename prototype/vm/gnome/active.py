import os
import threading
from contextlib import redirect_stdout
from pathlib import Path
from uuid import uuid4

from gi.repository import Gio, GLib

def check():
    assert os.getuid() != 0
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    name = bus.get_unique_name()
    try:
        path, = bus.call_sync(
            "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
            "GetSessionByPID", GLib.Variant("(u)", (os.getpid(),)), GLib.VariantType.new("(o)"),
            Gio.DBusCallFlags.NONE, 2500, None,
        ).unpack()
    except GLib.Error as exc:
        print("GNOME caller session resolution:", Gio.DBusError.get_remote_error(exc))
    else:
        props, = bus.call_sync(
            "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties", "GetAll",
            GLib.Variant("(s)", ("org.freedesktop.login1.Session",)), GLib.VariantType.new("(a{sv})"),
            Gio.DBusCallFlags.NONE, 2500, None,
        ).unpack()
        print("GNOME caller session:", {key: props[key] for key in ("Active", "Remote", "Class", "Type")})
    authority = "org.freedesktop.PolicyKit1"
    subject = ("system-bus-name", {"name": GLib.Variant("s", name)})
    action = "io.github.tobiasguta.SELinuxLens.read-recent-avcs"
    reply = bus.call_sync(
        authority, "/org/freedesktop/PolicyKit1/Authority", authority + ".Authority",
        "CheckAuthorization", GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 0, "")),
        GLib.VariantType.new("((bba{ss}))"), Gio.DBusCallFlags.NONE, 5000, None,
    )
    (authorized, challenge, _), = reply.unpack()
    print("GNOME caller noninteractive Polkit:", {"authorized": authorized, "challenge": challenge})
    assert not authorized and challenge, "Expected an explicit authorization challenge"
    check_id = uuid4().hex
    state = []
    finished = threading.Event()

    def begin():
        try:
            response = bus.call_sync(
                authority, "/org/freedesktop/PolicyKit1/Authority", authority + ".Authority",
                "CheckAuthorization", GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 1, check_id)),
                GLib.VariantType.new("((bba{ss}))"), Gio.DBusCallFlags.NONE, 8000, None,
            )
            (granted, _, _), = response.unpack()
            state.append("unexpected approval" if granted else "rejected")
        except GLib.Error as exc:
            state.append(Gio.DBusError.get_remote_error(exc) or exc.domain)
        finally:
            finished.set()

    worker = threading.Thread(target=begin)
    worker.start()
    if not finished.wait(1.5):
        bus.call_sync(
            authority, "/org/freedesktop/PolicyKit1/Authority", authority + ".Authority",
            "CancelCheckAuthorization", GLib.Variant("(s)", (check_id,)),
            GLib.VariantType.new("()"), Gio.DBusCallFlags.NONE, 3000, None,
        )
        print("GNOME caller real Polkit cancellation request accepted")
    worker.join()
    print("GNOME caller post-challenge outcome:", state[0])
    assert state[0] != "unexpected approval"


with Path("/tmp/selinux-lens-gnome-result.txt").open("x") as output, redirect_stdout(output):
    try:
        check()
    except Exception as error:
        print("GNOME probe error:", type(error).__name__, error)
        raise
