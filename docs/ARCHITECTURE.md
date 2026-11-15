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

`Denial`: audit serial (event_id), UTC timestamp, permissions, source/target contexts, target object class, command/name/PID, permissive value (true/false/unknown), raw AVC text. Context type parsing extracts field 3 from the colon-delimited context or returns `unknown`. Each denial optionally carries an `AuditEvidence` reference.

`AuditEvidence`: node if recorded, exact audit epoch, the denial's one-based output line number, related `SYSCALL`, `PATH`, and `PROCTITLE` records with their own kinds and line numbers, and the number of PATH items if unambiguously reported by SYSCALL. Correlation uses the capture, node, exact epoch and serial. Line numbers refer to the captured tool output. A missing record or item describes the usable evidence parsed from that output. Any command and path shown as AVC fields still come from the denial record.

`Snapshot`: SELinux mode, immutable tuple of Denial records, data source, user-visible diagnostic notice. The GUI stores the current Snapshot only in process memory.

`Interpretation`: observed text based on fields; possible explanations explicitly speculative; suggested checks that never execute commands automatically.

Report schema: `selinux-lens-report/v1` (see REPORT_FORMAT.md).

## Collection assumptions and known limitations

The collector runs `ausearch --input-logs -m AVC,USER_AVC -ts recent` without a shell or sudo. The parser accepts anchored audit headers and associates supported companion records from the same output. AVC/USER_AVC records require a denial message. Exact duplicate companion lines are shown once, with the first captured line number. Lines exceeding 16,384 characters are skipped and malformed records can be omitted. Older events are outside the query window, and audit configuration and policy may affect availability. The parser returns up to 200 denials, sorted newest first.

Binary stdout and stderr are drained concurrently with caps of 2 MB and 16 KiB, respectively, and a 12-second audit deadline. A cap, deadline or window close discards any partial output and terminates and reaps the collector process. The independent mode command has a three-second deadline and 1 KiB per stream. Successful audit output is decoded as UTF-8 with replacement for invalid bytes. Audit tool diagnostics are classified locally, and only the resulting status goes to the UI and report.

## Planned extension points

- `AuditSource` protocol: named source with capabilities, timestamps, permissions and provenance. Sources include unprivileged reader, constrained Polkit helper and fixture source.
- `AuditEventGroup`: group related denials in the list and consider source record hashes or original log offsets if a future source provides them.
- `PolicyInspector`: interfaces to installed policy and default-context tools, no writes.
- `Recommendation`: structured finding with evidence IDs, hypothesis, confidence limitations and suggested checks.
- `CaseStore`: optional, opt-in local history with retention boundaries.
- `ReportRenderer`: versioned JSON plus human-readable Markdown; independent redaction policy.
- Packaging: desktop entry, icon, appstream metadata, Fedora RPM; test across GTK/Adw versions.

## Architecture acceptance conditions

All UI updates happen on GTK's main thread. External records never interpreted as markup or executed as shell text. Unavailable/audit-denied/no-results are different states. Every hypothesis must be traced to an actual record or clearly labeled general guidance. Tests should run without GUI, SELinux or root by injecting subprocess runners.
