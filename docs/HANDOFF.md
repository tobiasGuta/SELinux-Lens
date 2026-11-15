# Implementation handoff to Codex

## What has been created

The initial v0.1 code implements a GTK4/Libadwaita inspection shell around read-only `getenforce` and `ausearch`, a regex-based AVC parser, deterministic interpretation, synthetic demo, JSON export, tests and CI. This is a preview: core tests can run without Fedora; **the GUI has now had a limited, user-reported Fedora GNOME smoke test; broader functionality remains unverified**.

## Do this first

1. Clone the repo on Fedora GNOME and read AGENTS.md, README and docs/SECURITY.md.
2. Run `make test && make compile`.
3. Re-test `bash run.sh --demo` as a regular user, including search, filters, keyboard support and export; initial launch/render has been observed.
4. Run `bash run.sh` as a regular user and improve its permission-denied empty state; ordinary-user denial has been observed.
5. Continue input hardening with per-line limits and safe rendering of untrusted control characters.
6. Review report redaction and export safety; treat both as security-critical.
7. Open PRs with evidence of actual testing rather than claiming an unverified app is production-ready.

## Fedora test observations — 2026-11-15

These are **user-reported observations from screenshots and terminal output**, not a full automated acceptance test:

- `bash run.sh --demo` opened successfully as a regular user on Fedora GNOME/Wayland. The window rendered three fictional AVC records, selected the first, and displayed contexts, observations, hypotheses, checks, and raw text. Search/filter interactions, export and full accessibility were **not** verified.
- `bash run.sh` opened successfully in real mode and displayed `SELinux: Enforcing`. It displayed **"Audit access was denied. The GUI does not use sudo; see docs/SECURITY.md."** and showed zero loaded events. This is a clear denial-access state, **not** evidence of zero system denials.
- The user's read-only administrative checks `sudo ausearch -m AVC,USER_AVC -ts recent` and `sudo ausearch -m AVC,USER_AVC -ts today` each returned `<no matches>`. These indicate no matching records in those audit queries at that time, not proof no denials occurred or were logged.
- Improve the real-mode empty state: replace unused detail headings with a focused permission explanation and next steps; keep that distinct from successfully querying an empty window.
- GitHub Actions for initial implementation commit `b802068694be4adff6eae927e051ef51538e80fb` passed Python 3.11 and 3.13 compile/unit checks.
- Exact Fedora/GTK/Libadwaita versions and the behavior of JSON export are not yet independently recorded.

## Known implementation gaps

- Basic GTK rendering was observed in a user screenshot; file chooser and end-to-end export have not been verified.
- The collector enforces stream budgets while reading and cancels on close. Individual audit lines still need a size limit and control-character handling.
- Audit collection reads only recent AVC/USER_AVC and does not correlate companion records.
- UI always displays raw AVC text locally; export redacts only target path/name, not all sensitive fields.
- No Polkit helper; ordinary Fedora user may see audit access denied.
- No RPM, desktop metadata, icons, integration tests or full live timeline.

## Minimal acceptance test for the next PR

No root GUI, no SELinux configuration writes, all unit tests passing, demo load and filters working on a real Fedora desktop, explicit no-access state, correct permissive interpretation, redacted JSON export, and documented evidence/limitations. Review any new privilege boundary separately and do not bundle a helper into a cosmetic PR.
