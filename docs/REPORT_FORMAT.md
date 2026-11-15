# JSON report formats

## Shareable GUI export — selinux-lens-report/v2

The desktop export writes UTF-8 JSON with a trailing newline. The report contains `schema`, a broad `source` of `demo` or `audit`, `selinux_mode`, the typed `collection_status`, `event_count` and an `events` array. Each event includes `permissions`, `target_class` and `permissive`. The last field is true, false, or null for an unknown disposition. Invalid text fields are empty.

The export omits times, serials, contexts, paths, process names and IDs, raw records, companion evidence and free-form diagnostics. Requested operations and target classes can still reveal system activity. Reports are created with private file permissions. Choose a new name for each export.

## Detailed API export — selinux-lens-report/v1

`report.serialize_report(snapshot)` writes indented UTF-8 JSON with a trailing newline and defaults to `include_paths=False`. Related audit records and their provenance are available in the local detail pane. V1 continues to export individual AVC observations and omits those companion records.

### Top-level fields

- `schema`: `selinux-lens-report/v1`.
- `generated_at_utc`: UTC ISO 8601 generation time.
- `source`: `ausearch` or `demo`.
- `selinux_mode`: `Enforcing`, `Permissive`, `Disabled`, `Unknown`, or `Demo (fictional)`.
- `notice`: collection warning/status string.
- `event_count`: number of exported individual AVC records.
- `redacted_target_paths`: whether export redacted target name/path.
- `events`: array of records.
- `warning`: explanation that findings are not proof of a vulnerability or misconfiguration.

### Per-record fields

`event_id`, `timestamp_utc`, `permissions`, `source_context`, `target_context`, `target_class`, `command`, `target`, `pid`, `permissive` (boolean or null), `observed`, `possible_explanations` (string array) and `next_checks` (string array).

`target` is `[redacted]` when a target exists and `include_paths=False`; otherwise it is an empty string when absent. Original raw lines are not included. Source/target contexts, commands and PIDs are **not redacted**; review before sharing.

### Stability policy

The `v1` schema name commits to the semantics of these keys; additive fields may be introduced with tests and updated docs. Breaking behavior requires `selinux-lens-report/v2` or a clear migration. The format represents **individual AVC lines**, not full serial-correlated audit incidents. Consumers must not interpret event_count as a measure of security severity.
