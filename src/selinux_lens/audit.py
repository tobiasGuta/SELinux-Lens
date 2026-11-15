"""Bounded, non-privileged SELinux audit collection and AVC parsing."""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
from datetime import datetime, timezone
from threading import Event
from time import monotonic
from typing import Callable

from .models import Denial, Snapshot

MAX_OUTPUT_BYTES = 2_000_000
MAX_ERROR_BYTES = 16_384
MAX_EVENTS = 200
_MODE_COMMAND = ["/usr/sbin/getenforce"]
_AUDIT_COMMAND = [
    "/usr/sbin/ausearch", "--input-logs", "-m", "AVC,USER_AVC", "-ts", "recent",
]
_READ_SIZE = 65_536
_CANCEL_POLL = 0.1

_AVC = re.compile(r"\btype=(?:AVC|USER_AVC)\b")
_DENIED = re.compile(r"\bavc:\s+denied\s*\{([^}]*)\}", re.IGNORECASE)
_EVENT = re.compile(r"\bmsg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)")
_FIELD = re.compile(r'(?<!\S)([A-Za-z_][A-Za-z_0-9]*)=(?:"((?:\\.|[^"\\])*)"|(\S+))')


def _fields(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in _FIELD.finditer(line):
        value = match.group(2) if match.group(2) is not None else match.group(3)
        values[match.group(1)] = value.replace(r'\"', '"')
    return values


def parse_ausearch(text: str, limit: int = MAX_EVENTS) -> tuple[Denial, ...]:
    """Parse AVC/USER_AVC records, skipping unrelated and malformed entries.

    Assumes the un-interpreted ausearch record format. Does not infer file
    paths from adjacent SYSCALL/PATH records or merge related serials.
    """
    if limit < 1:
        return ()
    results: list[Denial] = []
    for line in text.splitlines():
        if not _AVC.search(line):
            continue
        denial = _DENIED.search(line)
        audit_id = _EVENT.search(line)
        if denial is None or audit_id is None:
            continue
        fields = _fields(line)
        try:
            timestamp = datetime.fromtimestamp(
                float(audit_id.group(1)), timezone.utc
            ).isoformat(timespec="seconds")
        except (ValueError, OverflowError, OSError):
            continue
        perm = " ".join(denial.group(1).split())
        permissive_text = fields.get("permissive")
        permissive = (
            True if permissive_text == "1"
            else False if permissive_text == "0"
            else None
        )
        results.append(
            Denial(
                event_id=audit_id.group(2),
                timestamp_utc=timestamp,
                permissions=perm,
                source_context=fields.get("scontext", ""),
                target_context=fields.get("tcontext", ""),
                target_class=fields.get("tclass", ""),
                command=fields.get("comm", ""),
                target=fields.get("path", fields.get("name", "")),
                pid=fields.get("pid", ""),
                permissive=permissive,
                raw=line,
            )
        )
    # newest first; preserve arrival order for equal timestamps
    results.sort(key=lambda item: item.timestamp_utc, reverse=True)
    return tuple(results[:limit])


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
        else "No AVC denials in the recent audit window." if not events else ""
    )
    return Snapshot(mode, events, "ausearch", notice)
