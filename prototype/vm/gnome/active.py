import ctypes
import os
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path
from uuid import uuid4

from gi.repository import Gio, GLib


def inspect_process(bus):
    cgroup = Path("/proc/self/cgroup").read_text().strip()
    print("GNOME caller cgroup:", cgroup)
    print("GNOME caller kernel audit session:", Path("/proc/self/sessionid").read_text().strip())
    libsystemd = ctypes.CDLL("libsystemd.so.0")
    lookup = libsystemd.sd_pidfd_get_session
    lookup.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char_p))
    result = ctypes.c_char_p()
    fd = os.pidfd_open(os.getpid())
    try:
        status = lookup(fd, ctypes.byref(result))
        print("GNOME caller pidfd session:", result.value.decode() if status >= 0
              else os.strerror(-status))
        if status >= 0:
            ctypes.CDLL("libc.so.6").free(result)
    finally:
        os.close(fd)
    sessions, = bus.call_sync(
        "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
        "ListSessions", None, GLib.VariantType.new("(a(susso))"),
        Gio.DBusCallFlags.NONE, 2500, None,
    ).unpack()
    for session_id, uid, _, seat, path in sessions:
        if uid != os.getuid():
            continue
        props, = bus.call_sync(
            "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties", "GetAll",
            GLib.Variant("(s)", ("org.freedesktop.login1.Session",)),
            GLib.VariantType.new("(a{sv})"), Gio.DBusCallFlags.NONE, 2500, None,
        ).unpack()
        if props["Class"] == "user":
            print("GNOME caller same-UID session:", session_id, seat,
                  {k: props.get(k) for k in ("Scope", "Active", "Remote", "Type", "Service", "Audit")})


def check():
    assert os.getuid() != 0
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    inspect_process(bus)
    from prototype.audit_reader import SystemAuthorization

    auth = SystemAuthorization(bus)
    peer = auth.peer(bus.get_unique_name())
    assert peer is not None and peer.pid == os.getpid() and peer.uid == os.getuid()
    try:
        binding = auth.binding(peer)
    finally:
        os.close(peer.process_fd)
    print("GNOME caller reader binding:", binding)
    assert binding is None, "GNOME user-manager fixture unexpectedly has a session binding"
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


sys.path.insert(0, "/mnt/code")
with Path("/tmp/selinux-lens-gnome-result.txt").open("x") as output, redirect_stdout(output):
    try:
        check()
    except Exception as error:
        print("GNOME probe error:", type(error).__name__, error)
        raise
