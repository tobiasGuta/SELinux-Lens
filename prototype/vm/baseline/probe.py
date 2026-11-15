import os
import select

from gi.repository import Gio, GLib

bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
sender = bus.get_unique_name()
reply, fds = bus.call_with_unix_fd_list_sync(
    "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
    "GetConnectionCredentials", GLib.Variant("(s)", (sender,)), None,
    Gio.DBusCallFlags.NONE, 2500, None, None,
)
credentials, = reply.unpack()
assert credentials["UnixUserID"] == os.getuid() != 0
assert credentials["ProcessID"] == os.getpid()
fd = fds.get(credentials["ProcessFD"])
poll = select.poll()
poll.register(fd, select.POLLIN)
assert not poll.poll(0)
os.close(fd)
print("PASS real system-bus UID, PID and ProcessFD", flush=True)

try:
    bus.call_sync(
        "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
        "GetSessionByPID", GLib.Variant("(u)", (os.getpid(),)), GLib.VariantType.new("(o)"),
        Gio.DBusCallFlags.NONE, 2500, None,
    )
except GLib.Error as exc:
    assert Gio.DBusError.get_remote_error(exc) == "org.freedesktop.login1.NoSessionForPID"
    print("PASS real logind rejects sessionless test caller", flush=True)
else:
    raise AssertionError("Expected ordinary user outside a logind session")

name = "io.github.tobiasguta.SELinuxLens.read-recent-avcs"
authority = "org.freedesktop.PolicyKit1"
subject = ("system-bus-name", {"name": GLib.Variant("s", sender)})
reply = bus.call_sync(
    authority, "/org/freedesktop/PolicyKit1/Authority", authority + ".Authority",
    "CheckAuthorization", GLib.Variant("((sa{sv})sa{ss}us)", (subject, name, {}, 0, "")),
    GLib.VariantType.new("((bba{ss}))"), Gio.DBusCallFlags.NONE, 5000, None,
)
(authorized, challenge, _), = reply.unpack()
assert not authorized and not challenge
print("PASS real Polkit denied the sessionless caller for the draft action", flush=True)
