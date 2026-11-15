"""Explicit, locally saved JSON reports. Sensitive target paths redacted."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .explain import interpret
from .models import Snapshot


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
