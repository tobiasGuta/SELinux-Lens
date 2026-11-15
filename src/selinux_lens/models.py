"""Typed, deliberately small audit record model."""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Denial:
    event_id: str
    timestamp_utc: str
    permissions: str
    source_context: str
    target_context: str
    target_class: str
    command: str = ""
    target: str = ""
    pid: str = ""
    permissive: bool | None = None
    raw: str = field(default="", repr=False)

    @property
    def source_type(self) -> str:
        return _type_from_context(self.source_context)

    @property
    def target_type(self) -> str:
        return _type_from_context(self.target_context)

    @property
    def headline(self) -> str:
        action = self.permissions or "unknown action"
        origin = self.command or self.source_type or "unknown process"
        return f"{origin}: {action} on {self.target_class or 'object'}"


def _type_from_context(context: str) -> str:
    parts = context.split(":")
    return parts[2] if len(parts) >= 3 else "unknown"


@dataclass(frozen=True, slots=True)
class Snapshot:
    mode: str
    events: tuple[Denial, ...]
    source: str
    notice: str = ""
