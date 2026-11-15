# JSON report format: selinux-lens-report/v1

`report.serialize_report(snapshot)` writes indented UTF-8 JSON with a trailing newline. GUI export calls this with `include_paths=False`.

## Top-level fields

- `schema`: `selinux-lens-report/v1`.
- `generated_at_utc`: UTC ISO 8601 generation time.
- `source`: `ausearch` or `demo`.
- `selinux_mode`: `Enforcing`, `Permissive`, `Disabled`, `Unknown`, or `Demo (fictional)`.
- `notice`: collection warning/status string.
- `event_count`: number of exported individual AVC records.
- `redacted_target_paths`: whether export redacted target name/path.
- `events`: array of records.
- `warning`: explanation that findings are not proof of a vulnerability or misconfiguration.

## Per-record fields

`event_id`, `timestamp_utc`, `permissions`, `source_context`, `target_context`, `target_class`, `command`, `target`, `pid`, `permissive` (boolean or null), `observed`, `possible_explanations` (string array) and `next_checks` (string array).

`target` is `[redacted]` when a target exists and `include_paths=False`; otherwise it is an empty string when absent. Original raw lines are not included. Source/target contexts, commands and PIDs are **not redacted**; review before sharing.

## Stability policy

The `v1` schema name commits to the semantics of these keys; additive fields may be introduced with tests and updated docs. Breaking behavior requires `selinux-lens-report/v2` or a clear migration. The format represents **individual AVC lines**, not full serial-correlated audit incidents. Consumers must not interpret event_count as a measure of security severity.
