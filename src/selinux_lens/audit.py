"""Bounded, non-privileged SELinux audit collection and AVC parsing."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from typing import Callable

from .models import Denial, Snapshot

MAX_OUTPUT_BYTES = 2_000_000
MAX_EVENTS = 200

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


def _run(
    command: list[str],
    timeout: int = 12,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    return runner(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


def selinux_mode(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    try:
        result = _run(["getenforce"], timeout=3, runner=runner)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "Unknown"
    if result.returncode != 0:
        return "Unknown"
    mode = result.stdout.strip().capitalize()
    return mode if mode in {"Enforcing", "Permissive", "Disabled"} else "Unknown"


def load_recent(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Snapshot:
    """Read the last ~10 minutes of ausearch AVCs; never elevate privileges."""
    mode = selinux_mode(runner=runner)
    try:
        result = _run(
            ["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent"],
            runner=runner,
        )
    except FileNotFoundError:
        return Snapshot(
            mode, (), "ausearch",
            "ausearch is unavailable. Install audit and retry, or use Demo mode.",
        )
    except subprocess.TimeoutExpired:
        return Snapshot(mode, (), "ausearch", "Audit query timed out.")
    except OSError as exc:
        return Snapshot(mode, (), "ausearch", f"Cannot start ausearch: {exc}")

    output = result.stdout or ""
    error = (result.stderr or "").strip()
    if len(output.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        return Snapshot(
            mode, (), "ausearch",
            "Audit output exceeded the 2 MB safety limit. Narrow the time window.",
        )
    if result.returncode != 0:
        lower = error.lower()
        if any(term in lower for term in ("permission", "denied", "must be root", "not authorized")):
            return Snapshot(
                mode, (), "ausearch",
                "Audit access was denied. The GUI does not use sudo; see docs/SECURITY.md.",
            )
        if result.returncode == 1 and not error:
            return Snapshot(mode, (), "ausearch", "No AVC denials in the recent audit window.")
        return Snapshot(mode, (), "ausearch", f"Audit query failed: {error[:300] or 'unknown error'}")

    events = parse_ausearch(output)
    notice = (
        f"Showing the newest {MAX_EVENTS} denials from the recent audit window."
        if len(events) == MAX_EVENTS
        else "No AVC denials in the recent audit window." if not events else ""
    )
    return Snapshot(mode, events, "ausearch", notice)
