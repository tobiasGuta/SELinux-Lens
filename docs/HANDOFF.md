# Implementation handoff to Codex

## What has been created

The initial v0.1 code implements a GTK4/Libadwaita inspection shell around read-only `getenforce` and `ausearch`, a regex-based AVC parser, deterministic interpretation, synthetic demo, JSON export, tests and CI. Fedora 45 GNOME results and remaining checks are in [TESTING.md](TESTING.md#fedora-gnome-smoke-test).

## Do this first

1. Clone the repo on Fedora GNOME and read AGENTS.md, README and docs/SECURITY.md.
2. Run `make test && make compile`.
3. Run `bash run.sh --demo` as a regular user and resolve any GTK binding or UX issues found.
4. Run `bash run.sh` as a regular user and document audit permission behavior without using sudo for the GUI.
5. Implement a truly bounded collector (stream limits and cancellation), add tests and update docs.
6. Review report redaction and export safety; treat both as security-critical.
7. Open PRs with evidence of actual testing rather than claiming an unverified app is production-ready.

## Known implementation gaps

- GTK rendering and the in-process chooser were tested on Fedora 45. Portal-backed export and physical keyboard accessibility checks remain open.
- Audit output cap currently occurs after capture; memory use is not bounded by it.
- Audit collection reads only recent AVC/USER_AVC and does not correlate companion records.
- UI always displays raw AVC text locally; export redacts only target path/name, not all sensitive fields.
- No Polkit helper; ordinary Fedora user may see audit access denied.
- No RPM, desktop metadata, icons, integration tests or full live timeline.

## Minimal acceptance test for the next PR

No root GUI, no SELinux configuration writes, all unit tests passing, demo load and filters working on a real Fedora desktop, explicit no-access state, correct permissive interpretation, redacted JSON export, and documented evidence/limitations. Review any new privilege boundary separately and do not bundle a helper into a cosmetic PR.
