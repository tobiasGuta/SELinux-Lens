"""Explicit, locally saved JSON reports. Sensitive target paths redacted."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from errno import EINVAL
from pathlib import Path

from .explain import interpret
from .models import Snapshot

_REPORT_PERMISSIONS = re.compile(r"[A-Za-z0-9_ ]{1,256}")
_REPORT_CLASS = re.compile(r"[A-Za-z0-9_]{1,80}")


def build_report(snapshot: Snapshot, *, include_paths: bool = False) -> dict:
    events: list[dict] = []
    for event in snapshot.events:
        interpretation = interpret(event)
        events.append(
            {
                "event_id": event.event_id,
                "timestamp_utc": event.timestamp_utc,
                "permissions": event.permissions,
                "source_context": event.source_context,
                "target_context": event.target_context,
                "target_class": event.target_class,
                "command": event.command,
                "target": event.target if include_paths else "[redacted]" if event.target else "",
                "pid": event.pid,
                "permissive": event.permissive,
                "observed": interpretation.observed,
                "possible_explanations": list(interpretation.possible_explanations),
                "next_checks": list(interpretation.next_checks),
            }
        )
    return {
        "schema": "selinux-lens-report/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": snapshot.source,
        "selinux_mode": snapshot.mode,
        "notice": snapshot.notice,
        "event_count": len(events),
        "redacted_target_paths": not include_paths,
        "events": events,
        "warning": (
            "AVC observations are not proof of misconfiguration or exploitation. "
            "Review contexts and policy before making changes."
        ),
    }


def serialize_report(snapshot: Snapshot, *, include_paths: bool = False) -> str:
    return json.dumps(build_report(snapshot, include_paths=include_paths), indent=2) + "\n"


def serialize_shareable_report(snapshot: Snapshot) -> str:
    source = "demo" if snapshot.source == "demo" else "audit"
    modes = {"Enforcing", "Permissive", "Disabled"}
    mode = snapshot.mode if snapshot.mode in modes else "Unknown"
    payload = {
        "schema": "selinux-lens-report/v2",
        "source": source,
        "selinux_mode": "Demo (fictional)" if source == "demo" else mode,
        "collection_status": snapshot.status.value,
        "event_count": len(snapshot.events),
        "events": [
            {
                "permissions": event.permissions if _REPORT_PERMISSIONS.fullmatch(event.permissions)
                else "",
                "target_class": event.target_class if _REPORT_CLASS.fullmatch(event.target_class)
                else "",
                "permissive": event.permissive,
            }
            for event in snapshot.events
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def write_shareable_report(snapshot: Snapshot, destination: Path) -> None:
    """Publish a complete private report under a new name in the chosen directory."""
    if not destination.name or destination.name == "..":
        raise OSError(EINVAL, "Choose a report filename")
    data = serialize_shareable_report(snapshot)
    directory = _open_export_directory(destination.parent)
    try:
        fd = os.open(".", os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as report:
            report.write(data)
            report.flush()
            os.fsync(report.fileno())
            # The kernel's procfs link pins this open inode. The destination is new.
            os.link(
                f"/proc/self/fd/{report.fileno()}", destination.name,
                dst_dir_fd=directory, follow_symlinks=True,
            )
    finally:
        os.close(directory)


def _open_export_directory(path: Path) -> int:
    root, *components = path.absolute().parts
    if ".." in components:
        raise OSError(EINVAL, "Choose a direct path to the report folder")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open(root, flags)
    try:
        for component in components:
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise
