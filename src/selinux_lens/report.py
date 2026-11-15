"""Explicit, locally saved JSON reports. Sensitive target paths redacted."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex

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
    data = serialize_shareable_report(snapshot)
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    stage_name = ".selinux-lens-" + token_hex(16)
    try:
        os.mkdir(stage_name, mode=0o700, dir_fd=directory)
        try:
            stage = os.open(
                stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                metadata = os.fstat(stage)
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise PermissionError("Report staging directory is not private")
                _publish(stage, directory, destination.name, data)
            finally:
                os.close(stage)
        finally:
            os.rmdir(stage_name, dir_fd=directory)
    finally:
        os.close(directory)


def _publish(stage: int, directory: int, name: str, data: str) -> None:
    fd = os.open(
        "report", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=stage,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as report:
            report.write(data)
            report.flush()
            os.fsync(report.fileno())
        os.link(
            "report", name, src_dir_fd=stage, dst_dir_fd=directory, follow_symlinks=False
        )
    finally:
        os.unlink("report", dir_fd=stage)
