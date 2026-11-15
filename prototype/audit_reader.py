"""Uninstalled system-bus reader prototype. See docs/AUDIT_ACCESS.md."""

from __future__ import annotations

import os
import re
import select
import subprocess
import threading
from dataclasses import dataclass
from time import monotonic
from uuid import uuid4

from gi.repository import Gio, GLib

from selinux_lens import audit
from selinux_lens.models import Denial

BUS_NAME = "io.github.tobiasguta.SELinuxLens.AuditReader"
OBJECT_PATH = "/io/github/tobiasguta/SELinuxLens/AuditReader"
INTERFACE = BUS_NAME + "1"
ACTION = "io.github.tobiasguta.SELinuxLens.read-recent-avcs"
DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
LOGIN = "org.freedesktop.login1"
LOGIN_PATH = "/org/freedesktop/login1"
POLKIT = "org.freedesktop.PolicyKit1"
POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority"
POLKIT_INTERFACE = POLKIT + ".Authority"
FLAG = Gio.DBusMessageFlags.ALLOW_INTERACTIVE_AUTHORIZATION
RETURN_TYPE = "(sa(ssssssy))"
MAX_REPLY_BYTES = 256 * 1024
_XML = f"""
<node>
  <interface name="{INTERFACE}">
    <method name="GetRecentAvcs">
      <arg name="status" type="s" direction="out"/>
      <arg name="records" type="a(ssssssy)" direction="out"/>
    </method>
  </interface>
</node>
"""

Record = tuple[str, str, str, str, str, str, int]
Outcome = tuple[str, list[Record]]
_CONTEXT = re.compile(r"[A-Za-z0-9_:.,-]{1,512}")
_CLASS = re.compile(r"[A-Za-z0-9_]{1,80}")
_PERMISSIONS = re.compile(r"[A-Za-z0-9_ ]{1,256}")


@dataclass(frozen=True, slots=True)
class Peer:
    name: str
    uid: int
    pid: int
    process_fd: int

    def alive(self) -> bool:
        poll = select.poll()
        poll.register(self.process_fd, select.POLLIN)
        return not poll.poll(0)


@dataclass(frozen=True, slots=True)
class SessionBinding:
    owner: str
    path: str
    session_id: str
    timestamp: int
    seat: str


_ACTIVE_PROPERTIES = {"Active": True, "Remote": False, "Class": "user", "State": "active"}
_IDENTITY_PROPERTIES = {"User", "Id", "TimestampMonotonic", "Seat"}


class SystemAuthorization:
    def __init__(self, connection: Gio.DBusConnection) -> None:
        self._connection = connection

    def _call(
        self, name, path, interface, method, params, signature, *, timeout=1500, cancel=None
    ):
        return self._connection.call_sync(
            name, path, interface, method, params, GLib.VariantType.new(signature),
            Gio.DBusCallFlags.NONE, timeout, cancel,
        ).unpack()

    def peer(self, sender: str) -> Peer | None:
        reply, fd_list = self._connection.call_with_unix_fd_list_sync(
            DBUS, DBUS_PATH, DBUS, "GetConnectionCredentials", GLib.Variant("(s)", (sender,)),
            GLib.VariantType.new("(a{sv})"), Gio.DBusCallFlags.NONE, 1500, None, None,
        )
        credentials, = reply.unpack()
        pid = credentials.get("ProcessID")
        uid = credentials.get("UnixUserID")
        handle = credentials.get("ProcessFD")
        if not fd_list or not all(type(value) is int for value in (pid, uid, handle)):
            return None
        if pid <= 0 or uid < 0 or not 0 <= handle < fd_list.get_length():
            return None
        process_fd = fd_list.get(handle)
        return Peer(sender, uid, pid, process_fd)

    def binding(self, peer: Peer) -> SessionBinding | None:
        if not peer.alive():
            return None
        owner, = self._call(
            DBUS, DBUS_PATH, DBUS, "NameHasOwner", GLib.Variant("(s)", (peer.name,)), "(b)"
        )
        if not owner:
            return None
        logind_owner, = self._call(
            DBUS, DBUS_PATH, DBUS, "GetNameOwner", GLib.Variant("(s)", (LOGIN,)), "(s)"
        )
        try:
            path, = self._call(
                logind_owner, LOGIN_PATH, LOGIN + ".Manager", "GetSessionByPID",
                GLib.Variant("(u)", (peer.pid,)), "(o)",
            )
        except GLib.Error as error:
            if Gio.DBusError.get_remote_error(error) == LOGIN + ".NoSessionForPID":
                return None
            raise
        props, = self._call(
            logind_owner, path, "org.freedesktop.DBus.Properties", "GetAll",
            GLib.Variant("(s)", (LOGIN + ".Session",)), "(a{sv})",
        )
        user = props.get("User")
        seat = props.get("Seat")
        session_id = props.get("Id")
        timestamp = props.get("TimestampMonotonic")
        if not (
            isinstance(user, (tuple, list))
            and len(user) == 2
            and user[0] == peer.uid
            and isinstance(seat, (tuple, list))
            and len(seat) == 2
            and isinstance(seat[0], str)
            and seat[0]
            and isinstance(session_id, str)
            and session_id
            and type(timestamp) is int
            and timestamp > 0
            and all(props.get(key) == value for key, value in _ACTIVE_PROPERTIES.items())
            and peer.alive()
        ):
            return None
        return SessionBinding(logind_owner, path, session_id, timestamp, seat[0])

    def authorize(self, peer: Peer, cancel: Gio.Cancellable) -> bool:
        request_id = uuid4().hex
        subject = ("system-bus-name", {"name": GLib.Variant("s", peer.name)})
        try:
            (authorized, _, details), = self._call(
                POLKIT, POLKIT_PATH, POLKIT_INTERFACE, "CheckAuthorization",
                GLib.Variant("((sa{sv})sa{ss}us)", (subject, ACTION, {}, 1, request_id)),
                "((bba{ss}))", timeout=60_000, cancel=cancel,
            )
        except GLib.Error:
            try:
                self._call(
                    POLKIT, POLKIT_PATH, POLKIT_INTERFACE, "CancelCheckAuthorization",
                    GLib.Variant("(s)", (request_id,)), "()",
                )
            except GLib.Error:
                pass
            raise
        return authorized and not {
            "polkit.temporary_authorization_id",
            "polkit.retains_authorization_after_challenge",
        }.intersection(details)


def _project(event: Denial) -> Record:
    epoch = event.evidence.epoch if event.evidence is not None else ""
    return (
        epoch, event.event_id,
        event.permissions if _PERMISSIONS.fullmatch(event.permissions) else "",
        event.source_context if _CONTEXT.fullmatch(event.source_context) else "",
        event.target_context if _CONTEXT.fullmatch(event.target_context) else "",
        event.target_class if _CLASS.fullmatch(event.target_class) else "",
        {None: 0, False: 1, True: 2}[event.permissive],
    )


def _collect(cancel: threading.Event) -> Outcome:
    try:
        result = audit._run(
            ["/usr/sbin/ausearch", "--input-logs", "--format", "default", "-m", "AVC,USER_AVC",
             "-ts", "recent"],
            timeout=12, output_limit=audit.MAX_OUTPUT_BYTES, error_limit=audit.MAX_ERROR_BYTES,
            cancel=cancel,
        )
    except audit.CollectionCancelled:
        return "cancelled", []
    except audit.CaptureLimitReached:
        return "capped", []
    except subprocess.TimeoutExpired:
        return "timed_out", []
    except OSError:
        return "unavailable", []
    if result.returncode == 1 and not result.stdout and result.stderr.strip() == b"<no matches>":
        return "empty", []
    if result.returncode or result.stderr:
        return "unavailable", []
    events = audit.parse_ausearch(
        result.stdout.decode("utf-8", errors="replace"), limit=audit.MAX_EVENTS + 1
    )
    if not events:
        return ("incomplete" if result.stdout.strip() else "empty"), []
    status = "capped" if len(events) > audit.MAX_EVENTS else "ok"
    return status, [_project(event) for event in events[:audit.MAX_EVENTS]]


def _reply(status: str, records: list[Record]) -> GLib.Variant:
    payload: list[Record] = []
    size_budget = MAX_REPLY_BYTES - 512
    for record in records[:audit.MAX_EVENTS]:
        # D-Bus adds length, alignment and termination to each string.
        size_budget -= sum(len(value.encode("utf-8")) for value in record[:-1]) + 64
        if size_budget < 0:
            break
        payload.append(record)
    if len(payload) < len(records):
        status = "capped"
    result = GLib.Variant(RETURN_TYPE, (status, payload))
    if result.get_size() > MAX_REPLY_BYTES:
        return GLib.Variant(RETURN_TYPE, ("capped", []))
    return result


def _wire_reply(
    request: Gio.DBusMessage, sender: str, outcome: Outcome
) -> GLib.Variant:
    body = _reply(*outcome)
    message = Gio.DBusMessage.new_method_reply(request)
    message.set_sender(sender)
    message.set_body(body)
    if len(message.to_blob(Gio.DBusCapabilityFlags.NONE)) > MAX_REPLY_BYTES:
        return _reply("capped", [])
    return body


class AuditReader:
    def __init__(self, connection, authorization=None, collect=_collect):
        self._authorization = authorization if authorization is not None else SystemAuthorization(
            connection
        )
        self._collect = collect
        self._peer = None
        self._binding = None
        self._cancel = threading.Event()
        self._auth_cancel = Gio.Cancellable()
        self._next_attempt = 0.0
        self._recent_uids: dict[int, float] = {}
        self._connection = connection
        definition = Gio.DBusNodeInfo.new_for_xml(_XML)
        self._registration = connection.register_object(
            OBJECT_PATH, definition.interfaces[0], self._request, None, None
        )
        self._subscriptions = [
            connection.signal_subscribe(
                DBUS, DBUS, "NameOwnerChanged", DBUS_PATH, None, Gio.DBusSignalFlags.NONE,
                self._owner_changed,
            ),
            connection.signal_subscribe(
                LOGIN, "org.freedesktop.DBus.Properties", "PropertiesChanged", None,
                LOGIN + ".Session", Gio.DBusSignalFlags.NONE, self._session_changed,
            ),
            connection.signal_subscribe(
                LOGIN, LOGIN + ".Manager", "SessionRemoved", LOGIN_PATH, None,
                Gio.DBusSignalFlags.NONE, self._session_removed,
            ),
        ]

    def close(self):
        self._cancel_request()
        for subscription in self._subscriptions:
            self._connection.signal_unsubscribe(subscription)
        self._connection.unregister_object(self._registration)

    def _cancel_request(self):
        self._cancel.set()
        self._auth_cancel.cancel()

    def _owner_changed(self, _connection, _sender, _path, _iface, _signal, values):
        name, previous, owner = values.unpack()
        binding = self._binding
        if (name == self._peer and not owner) or (
            binding is not None and name == LOGIN
            and previous == binding.owner and owner != binding.owner
        ):
            self._cancel_request()

    def _session_changed(self, _connection, sender, path, _iface, _signal, values):
        binding = self._binding
        if binding is None or (sender, path) != (binding.owner, binding.path):
            return
        _, changed, invalidated = values.unpack()
        if (
            _IDENTITY_PROPERTIES.intersection(changed)
            or (_IDENTITY_PROPERTIES | _ACTIVE_PROPERTIES.keys()).intersection(invalidated)
            or any(key in changed and changed[key] != value
                   for key, value in _ACTIVE_PROPERTIES.items())
        ):
            self._cancel_request()

    def _session_removed(self, _connection, sender, _path, _iface, _signal, values):
        binding = self._binding
        session_id, path = values.unpack()
        if binding is not None and (sender, session_id, path) == (
            binding.owner, binding.session_id, binding.path
        ):
            self._cancel_request()

    def _same_session(self, peer, binding):
        return not self._cancel.is_set() and self._authorization.binding(peer) == binding

    def _request(self, _connection, sender, _path, _interface, method, params, invocation):
        flags = invocation.get_message().get_flags()
        if not (
            sender and sender.startswith(":") and flags & FLAG
            and not flags & Gio.DBusMessageFlags.NO_REPLY_EXPECTED
            and method == "GetRecentAvcs" and params.get_type_string() == "()"
        ):
            invocation.return_value(_reply("denied", []))
            return
        if self._peer is not None:
            invocation.return_value(_reply("busy", []))
            return
        now = monotonic()
        if now < self._next_attempt:
            invocation.return_value(_reply("rate_limited", []))
            return
        self._next_attempt = now + 2
        self._peer = sender
        self._cancel.clear()
        self._auth_cancel = Gio.Cancellable()
        worker = threading.Thread(
            target=self._serve, args=(sender, invocation), name="audit-reader-request"
        )
        try:
            worker.start()
        except RuntimeError:
            self._peer = None
            invocation.return_value(_reply("unavailable", []))

    def _serve(self, sender, invocation):
        peer = None
        outcome: Outcome = ("unavailable", [])
        try:
            peer = self._authorization.peer(sender)
            binding = self._authorization.binding(peer) if peer is not None else None
            if binding is None:
                outcome = ("denied", [])
            else:
                self._binding = binding
                now = monotonic()
                self._recent_uids = {
                    uid: deadline for uid, deadline in self._recent_uids.items() if deadline > now
                }
                if peer.uid in self._recent_uids:
                    outcome = ("rate_limited", [])
                elif not self._same_session(peer, binding):
                    outcome = ("cancelled", [])
                else:
                    self._recent_uids[peer.uid] = now + 15
                    if self._authorization.authorize(peer, self._auth_cancel):
                        if not self._same_session(peer, binding):
                            outcome = ("cancelled", [])
                        else:
                            collected = self._collect(self._cancel)
                            if self._same_session(peer, binding):
                                outcome = collected
                            else:
                                outcome = ("cancelled", [])
                    else:
                        outcome = ("denied", [])
        except (GLib.Error, OSError):
            pass
        finally:
            if peer is not None:
                os.close(peer.process_fd)
            GLib.idle_add(self._finish, invocation, outcome)

    def _finish(self, invocation, outcome):
        self._peer = None
        self._binding = None
        if self._cancel.is_set():
            outcome = ("cancelled", [])
        try:
            body = _wire_reply(invocation.get_message(), self._connection.get_unique_name(), outcome)
        except GLib.Error:
            body = _reply("unavailable", [])
        invocation.return_value(body)
        return GLib.SOURCE_REMOVE
