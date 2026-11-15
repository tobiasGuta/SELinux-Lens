# Development handoff

## What has been created

The initial v0.1 code implements a GTK4/Libadwaita inspection shell around read-only `getenforce` and `ausearch`, a regex-based AVC parser, deterministic interpretation, synthetic demo, JSON export, tests and CI. Fedora 45 GNOME results and remaining checks are in [TESTING.md](TESTING.md#fedora-gnome-smoke-test).

## Do this first

1. Clone the repo on Fedora GNOME and read AGENTS.md, README and docs/SECURITY.md.
2. Run `make test && make compile`.
3. Finish physical keyboard, magnifier and portal-backed export testing on Fedora GNOME.
4. Verify correlated records against an independently authorized populated Fedora audit query.
5. Review the authorized audit interface and validate real Polkit, peer eligibility and a confined service identity in an isolated Fedora VM. [Audit access design](AUDIT_ACCESS.md)
6. Verify the shareable v2 desktop export on different local filesystems. Keep the detailed v1 API compatible.
7. Open PRs with evidence of actual testing rather than claiming an unverified app is production-ready.

## Fedora test observations — 2026-11-15

These are **user-reported observations from screenshots and terminal output**, not a full automated acceptance test:

- `bash run.sh --demo` opened successfully as a regular user on Fedora GNOME/Wayland. The window rendered three fictional AVC records, selected the first, and displayed contexts, observations, hypotheses, checks, and raw text. Search/filter interactions, export and full accessibility were **not** verified.
- `bash run.sh` opened successfully in real mode and displayed `SELinux: Enforcing`. It displayed **"Audit access was denied. The GUI does not use sudo; see docs/SECURITY.md."** and showed zero loaded events. This is a clear denial-access state, **not** evidence of zero system denials.
- The user's read-only administrative checks `sudo ausearch -m AVC,USER_AVC -ts recent` and `sudo ausearch -m AVC,USER_AVC -ts today` each returned `<no matches>`. These indicate no matching records in those audit queries at that time, not proof no denials occurred or were logged.
- GitHub Actions for initial implementation commit `b802068694be4adff6eae927e051ef51538e80fb` passed Python 3.11 and 3.13 compile/unit checks.
- See [the follow-up Fedora 45 checks](TESTING.md#fedora-gnome-smoke-test) for exact versions and in-process JSON export.

## Known implementation gaps

- GTK rendering and the in-process chooser were tested on Fedora 45. Portal-backed export and physical keyboard accessibility checks remain open.
- The collector enforces stream budgets while reading and cancels on close. Audit lines and previews have separate limits.
- The UI correlates supported companion records within one capture and reports missing records and PATH items. Availability on live systems depends on the audit source.
- The UI renders bounded AVC and companion previews locally. The desktop exports a shareable v2 summary to a private file under a new name. The detailed v1 API keeps its earlier field set.
- No Polkit helper; ordinary Fedora user may see audit access denied.
- No RPM, desktop metadata, icons, integration tests or full live timeline.

## v0.1.1 candidate observations

The user reported a current checkout and 38 passing tests. On Fedora, the demo showed three records with incomplete PATH evidence, and normal mode showed **Audit access required** under enforcing SELinux with export disabled. An inspected shareable v2 demo report contained only the three permitted event fields. The observed workflow and remaining checks are recorded in the test guide. [User-observed validation](TESTING.md#user-observed-v011-candidate-check)

## Minimal acceptance test for the next PR

No root GUI, no SELinux configuration writes, all unit tests passing, demo load and filters working on a real Fedora desktop, explicit no-access state, correct permissive interpretation, redacted JSON export, and documented evidence/limitations. Review any new privilege boundary separately and do not bundle a helper into a cosmetic PR.
