# Architecture and data flow

## Current v0.1 modules

```text
  run.sh / console script
           |
       __main__.py
           |
        gui.py (GTK4 + Libadwaita main loop)
         |             |
   worker thread       +--> report.py (JSON, redaction)
         |                         |
      audit.py ----------------> models.py <--- explain.py
         |                         ^
   getenforce + ausearch           |
                    demo.py -------+
```

Layer separation prevents tests from requiring a graphical environment or privileged audit access. `__main__` lazily imports the GUI. UI invokes blocking audit collection in a worker and publishes the resulting immutable Snapshot with `GLib.idle_add`. No long-lived background service, HTTP listener or database.

## Data contract

`Denial`: audit serial (event_id), UTC timestamp, permissions, source/target contexts, target object class, command/name/PID, permissive value (true/false/unknown), raw AVC text. Context type parsing extracts field 3 from the colon-delimited context or returns `unknown`. This is an **individual AVC record**, not a fully correlated event.

`Snapshot`: SELinux mode, immutable tuple of Denial records, data source, user-visible diagnostic notice. The GUI stores the current Snapshot only in process memory.

`Interpretation`: observed text based on fields; possible explanations explicitly speculative; suggested checks that never execute commands automatically.

Report schema: `selinux-lens-report/v1` (see REPORT_FORMAT.md).

## Collection assumptions and known limitations

Current command: `ausearch -m AVC,USER_AVC -ts recent`. No shell and no sudo. Parsed lines must have a type marker, `avc: denied { ... }` and a `msg=audit(epoch:serial)` identity. Adjacent SYSCALL/PATH/PROCTITLE messages and multi-record correlations are not implemented. Old events outside the 'recent' window are not shown; audit configuration and policy may affect record availability. 200 results returned at most, sorted newest first. Fixed 12-second subprocess timeout. Post-capture 2 MB output rejection protects downstream parsing but does **not** enforce a hard RAM or pipe limit before capture: fix early in next milestone.

## Planned extension points

- `AuditSource` protocol: named source with capabilities, timestamps, permissions and provenance. Sources include unprivileged reader, constrained Polkit helper and fixture source.
- `AuditEventGroup`: full serial-based correlation; preserve source record hashes/offsets and explicit missing fields.
- `PolicyInspector`: interfaces to installed policy and default-context tools, no writes.
- `Recommendation`: structured finding with evidence IDs, hypothesis, confidence limitations and suggested checks.
- `CaseStore`: optional, opt-in local history with retention boundaries.
- `ReportRenderer`: versioned JSON plus human-readable Markdown; independent redaction policy.
- Packaging: desktop entry, icon, appstream metadata, Fedora RPM; test across GTK/Adw versions.

## Architecture acceptance conditions

All UI updates happen on GTK's main thread. External records never interpreted as markup or executed as shell text. Unavailable/audit-denied/no-results are different states. Every hypothesis must be traced to an actual record or clearly labeled general guidance. Tests should run without GUI, SELinux or root by injecting subprocess runners.
