"""Bounded, non-privileged SELinux audit collection and AVC parsing."""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event
from time import monotonic
from typing import Callable

from .models import AuditEvidence, Denial, RelatedAuditRecord, Snapshot

MAX_OUTPUT_BYTES = 2_000_000
MAX_ERROR_BYTES = 16_384
MAX_EVENTS = 200
MAX_LINE_CHARS = 16_384
_MODE_COMMAND = ["/usr/sbin/getenforce"]
_AUDIT_COMMAND = [
    "/usr/sbin/ausearch", "--input-logs", "-m", "AVC,USER_AVC", "-ts", "recent",
]
_READ_SIZE = 65_536
_CANCEL_POLL = 0.1

_HEADER = re.compile(
    r"(?:node=([A-Za-z0-9_.:\-]+)[ \t]+)?type=([A-Z_]+)[ \t]+"
    r"msg=audit\(([0-9]{1,19}(?:\.[0-9]{1,9})?):([0-9]{1,20})\):[ \t]*(.*)"
)
_DENIED = re.compile(
    r"avc:[ \t]+denied[ \t]*\{[ \t]*([A-Za-z0-9_]+(?:[ \t]+[A-Za-z0-9_]+)*)"
    r"[ \t]*\}(?:[ \t]+for)?(?=[ \t]|$)",
    re.IGNORECASE,
)
_FIELD = re.compile(
    r"""[ \t]*([A-Za-z_][A-Za-z_0-9]*)=(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s'"]+))"""
    r"(?=[ \t]|$)"
)
_UINT = re.compile(r"[0-9]{1,9}")
_HEX = re.compile(r"[0-9A-Fa-f]+")
_AVC_TYPES = {"AVC", "USER_AVC"}
_RELATED_TYPES = {"SYSCALL", "PATH", "PROCTITLE"}

AuditIdentity = tuple[str | None, str, str]


def _fields(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    ambiguous: set[str] = set()
    cursor = 0
    while match := _FIELD.match(text, cursor):
        key, double, single, plain = match.groups()
        if double is not None:
            value = double.replace(r'\"', '"')
        elif single is not None:
            value = single.replace(r"\'", "'")
        else:
            value = plain
        if values.setdefault(key, value) != value:
            ambiguous.add(key)
        cursor = match.end()
    for key in ambiguous:
        del values[key]
    return values


def _denial(
    kind: str, identity: AuditIdentity, body: str, raw: str
) -> Denial | None:
    outer_pid = ""
    match = _DENIED.match(body)
    if match is None and kind == "USER_AVC":
        outer = _fields(body)
        body = outer.get("msg", "")
        outer_pid = outer.get("pid", "")
        match = _DENIED.match(body)
    if match is None:
        return None

    _, epoch, serial = identity
    seconds, _, _ = epoch.partition(".")
    try:
        timestamp = datetime.fromtimestamp(int(seconds), timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return None
    fields = _fields(body[match.end():])
    return Denial(
        event_id=serial,
        timestamp_utc=timestamp,
        permissions=" ".join(match[1].split()),
        source_context=fields.get("scontext", ""),
        target_context=fields.get("tcontext", ""),
        target_class=fields.get("tclass", ""),
        command=fields.get("comm", ""),
        target=fields.get("path", fields.get("name", "")),
        pid=fields.get("pid", outer_pid),
        permissive={"1": True, "0": False}.get(fields.get("permissive")),
        raw=raw,
    )


def _related_record(
    kind: str, body: str, raw: str, line_number: int
) -> tuple[RelatedAuditRecord, int | None] | None:
    fields = _fields(body)
    expected_paths = None
    path_item = None
    if kind == "SYSCALL":
        if not _HEX.fullmatch(fields.get("arch", "")) or not _UINT.fullmatch(
            fields.get("syscall", "")
        ):
            return None
        items = fields.get("items", "")
        if _UINT.fullmatch(items):
            expected_paths = int(items)
    elif kind == "PATH":
        item = fields.get("item", "")
        if not _UINT.fullmatch(item) or "name" not in fields:
            return None
        path_item = int(item)
    else:
        title = fields.get("proctitle", "")
        if title != "(null)" and (len(title) % 2 or not _HEX.fullmatch(title)):
            return None
    return RelatedAuditRecord(kind, line_number, raw, path_item), expected_paths


def _audit_time(identity: AuditIdentity) -> tuple[int, int]:
    _, epoch, _ = identity
    seconds, _, fraction = epoch.partition(".")
    return int(seconds), int(fraction.ljust(9, "0"))


def parse_ausearch(text: str, limit: int = MAX_EVENTS) -> tuple[Denial, ...]:
    """Parse denials and associate supported records by capture, node and full audit ID."""
    if limit < 1:
        return ()
    results: list[tuple[AuditIdentity, int, Denial]] = []
    companions: dict[
        AuditIdentity, dict[str, tuple[RelatedAuditRecord, int | None]]
    ] = defaultdict(dict)
    for line_number, line in enumerate(text.split("\n"), 1):
        if len(line) > MAX_LINE_CHARS:
            continue
        # Auditd may append interpreted fields after a group separator.
        # Parse the original portion. Keep the line for local provenance.
        match = _HEADER.fullmatch(line.partition("\x1d")[0])
        if match is None:
            continue
        node, kind, epoch, serial, body = match.groups()
        identity = (node, epoch, serial)
        if kind in _AVC_TYPES:
            event = _denial(kind, identity, body, line)
            if event is not None:
                results.append((identity, line_number, event))
        elif kind in _RELATED_TYPES:
            record = _related_record(kind, body, line, line_number)
            if record is not None:
                companions[identity].setdefault(line, record)

    results.sort(key=lambda record: _audit_time(record[0]), reverse=True)
    grouped: dict[AuditIdentity, tuple[tuple[RelatedAuditRecord, ...], int | None]] = {}
    denials: list[Denial] = []
    for identity, line_number, event in results[:limit]:
        if identity not in grouped:
            records = companions.get(identity, {}).values()
            related = tuple(record for record, _ in records)
            path_counts = {count for _, count in records if count is not None}
            expected_paths = next(iter(path_counts)) if len(path_counts) == 1 else None
            grouped[identity] = related, expected_paths
        related, expected_paths = grouped[identity]
        node, epoch, _ = identity
        evidence = AuditEvidence(node, epoch, line_number, related, expected_paths)
        denials.append(replace(event, evidence=evidence))
    return tuple(denials)


class CaptureLimitReached(Exception):
    """A command produced more bytes than its stream budget."""


class CollectionCancelled(Exception):
    """The caller requested cancellation."""


def _run(
    command: list[str],
    *,
    timeout: float,
    output_limit: int,
    error_limit: int,
    cancel: Event | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if cancel is not None and cancel.is_set():
        raise CollectionCancelled
    deadline = monotonic() + timeout
    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env={"LC_ALL": "C"},
        start_new_session=True,
    ) as process:
        stdout = bytearray()
        stderr = bytearray()
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, (stdout, output_limit))
                selector.register(process.stderr, selectors.EVENT_READ, (stderr, error_limit))
                while True:
                    if cancel is not None and cancel.is_set():
                        raise CollectionCancelled
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    delay = min(remaining, _CANCEL_POLL) if cancel is not None else remaining
                    if not selector.get_map():
                        try:
                            returncode = process.wait(timeout=delay)
                        except subprocess.TimeoutExpired:
                            continue
                        completed = True
                        return subprocess.CompletedProcess(
                            command, returncode, bytes(stdout), bytes(stderr)
                        )

                    for key, _ in selector.select(delay):
                        buffer, limit = key.data
                        available = limit - len(buffer)
                        chunk = os.read(key.fd, min(_READ_SIZE, available + 1))
                        if len(chunk) > available:
                            raise CaptureLimitReached
                        if chunk:
                            buffer.extend(chunk)
                        else:
                            selector.unregister(key.fileobj)
        finally:
            if not completed:
                try:
                    # Signal the group before reaping its leader, even if a
                    # descendant is the only process still holding a pipe open.
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def selinux_mode(
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _run,
    *,
    cancel: Event | None = None,
) -> str:
    try:
        result = runner(
            _MODE_COMMAND, timeout=3, output_limit=1024, error_limit=1024, cancel=cancel
        )
    except (OSError, subprocess.TimeoutExpired, CaptureLimitReached):
        return "Unknown"
    if result.returncode != 0:
        return "Unknown"
    mode = result.stdout.strip().capitalize()
    return {b"Enforcing": "Enforcing", b"Permissive": "Permissive", b"Disabled": "Disabled"}.get(
        mode, "Unknown"
    )


def load_recent(
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _run,
    *,
    cancel: Event | None = None,
) -> Snapshot:
    """Read the last ~10 minutes of ausearch AVCs; never elevate privileges."""
    mode = "Unknown"
    try:
        mode = selinux_mode(runner=runner, cancel=cancel)
        result = runner(
            _AUDIT_COMMAND, timeout=12, output_limit=MAX_OUTPUT_BYTES,
            error_limit=MAX_ERROR_BYTES, cancel=cancel,
        )
    except CollectionCancelled:
        return Snapshot(mode, (), "ausearch", "Audit query cancelled.")
    except FileNotFoundError:
        return Snapshot(
            mode, (), "ausearch",
            "ausearch is unavailable. Install audit and retry, or use Demo mode.",
        )
    except PermissionError:
        return Snapshot(mode, (), "ausearch", "Audit access was denied.")
    except subprocess.TimeoutExpired:
        return Snapshot(mode, (), "ausearch", "Audit query timed out.")
    except CaptureLimitReached:
        return Snapshot(
            mode, (), "ausearch",
            "Audit query exceeded its output safety limit. No records were loaded.",
        )
    except OSError:
        return Snapshot(mode, (), "ausearch", "Could not run the audit query.")

    if result.returncode != 0:
        error = result.stderr.strip().lower()
        if any(term in error for term in (
            b"permission denied", b"operation not permitted", b"must be root", b"not authorized"
        )):
            return Snapshot(
                mode, (), "ausearch",
                "Audit access was denied. The GUI does not use sudo; see docs/SECURITY.md.",
            )
        if result.returncode == 1 and not result.stdout and error == b"<no matches>":
            return Snapshot(mode, (), "ausearch", "No AVC denials in the recent audit window.")
        return Snapshot(mode, (), "ausearch", f"Audit query failed (exit {result.returncode}).")

    events = parse_ausearch(result.stdout.decode("utf-8", errors="replace"))
    notice = (
        f"Showing the newest {MAX_EVENTS} denials from the recent audit window."
        if len(events) == MAX_EVENTS
        else "No parseable AVC denials in the recent audit output." if not events else ""
    )
    return Snapshot(mode, events, "ausearch", notice)
