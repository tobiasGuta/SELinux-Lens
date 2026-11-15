# Architecture decisions

## ADR-001: Native GTK4/Libadwaita (accepted)
Why: Fedora GNOME familiarity, native accessibility and theming, low overhead, no Electron. Tradeoff: GI versions differ; must smoke-test on supported Fedora versions.

## ADR-002: Read-only CLI backend before privileged helper (accepted)
Why: safe initial boundary, fast deterministic tests, no unaudited root code. Tradeoff: many ordinary users lack audit read permission; v0.1 therefore has degraded mode and demo. Future helper requires explicit threat-model approval.

## ADR-003: No policy changes (accepted)
Why: 'allow' changes can weaken MAC containment and a denial is not proof of misconfiguration. Any future remediation capability starts as human-reviewed, read-only preview with evidence, not automatic application.

## ADR-004: Observed facts vs possible explanations (accepted)
Why: AVC messages by themselves are incomplete evidence. Preserve unknowns and never imply the source of a denial has been definitively identified.

## ADR-005: Core Python without GTK imports (accepted)
Why: maintain testability in non-Fedora CI, isolate I/O and enable future parsers/backends. GUI only imports from established domain modules.

## ADR-006: Short, recent window and 200-event cap (temporary)
The fixed time window and record cap keep the event list usable. The collector enforces stdout and stderr budgets while reading. A query that hits either budget reports the cap and discards partial output. Older events remain outside the query window.

## ADR-007: In-memory state, explicit JSON export (accepted for v0.1)
Why: avoid accidental privacy-sensitive databases. Reports redact target names/paths and omit raw records, though other identifying data remains. Future export may add granular redaction and safe atomic writes.

## ADR-008: No mandatory AI (accepted)
Why: deterministic audit interpretation can be tested and cited. Future optional explanations must not fabricate policy or override observed evidence.
