"""Evidence-first interpretation. Never assert a root cause from AVC text alone."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Denial


@dataclass(frozen=True, slots=True)
class Interpretation:
    observed: str
    possible_explanations: tuple[str, ...]
    next_checks: tuple[str, ...]


def interpret(event: Denial) -> Interpretation:
    disposition = (
        "The AVC is marked permissive=1: the policy would deny the action, "
        "but this record alone does not establish that it was blocked."
        if event.permissive is True
        else "The AVC is marked permissive=0: SELinux reported this action denied."
        if event.permissive is False
        else "The record does not specify whether this denial was permissive."
    )
    observed = (
        f"{event.source_type} requested [{event.permissions}] on a "
        f"{event.target_class or 'target'} labeled {event.target_type}. "
        + disposition
    )
    ideas: list[str] = []
    if event.source_type == "httpd_t" and event.target_type == "user_home_t":
        ideas.append(
            "A web service accessing home-directory-labeled content can be "
            "a location or labeling mismatch. Confirm the intended service path."
        )
    if event.target_type in {"default_t", "unlabeled_t"}:
        ideas.append(
            "The target has a generic or unlabeled type. Investigate the "
            "expected label before proposing any change."
        )
    if not ideas:
        ideas.append(
            "A policy restriction, unexpected file context, or application "
            "configuration may be involved. This event does not prove which."
        )
    checks = (
        "Verify the service's expected behavior and target resource.",
        "Inspect the target's current and expected SELinux labels.",
        "Compare relevant installed SELinux policy and local overrides.",
        "Correlate this event with the same audit serial and service logs.",
    )
    return Interpretation(observed, tuple(ideas), checks)
