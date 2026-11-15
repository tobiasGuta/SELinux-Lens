# Testing and verification

## Developer checks (without root or GNOME)

```bash
make compile
make test
PYTHONPATH=src python3 -m selinux_lens --help
PYTHONPATH=src python3 -m selinux_lens --version
```

Unit tests exercise AVC parsing, record ordering, permissive semantics, missing commands, permission denial, explicit no matches, redaction and deterministic explanations. Synthetic subprocesses exercise independent stdout and stderr limits, exit status, hanging children, cancellation, and child reaping. Invalid UTF-8 and private error text are covered by collection tests. Core modules intentionally import no GTK.

GitHub Actions runs compile/tests on Python 3.11 and 3.13. Passing these checks **does not validate runtime GTK compatibility, SELinux policy behavior, audit access or safe use on a live workstation**.

## Fedora GNOME manual checklist (partially completed; see observations below)

1. On Fedora GNOME with a normal user, install `python3 python3-gobject gtk4 libadwaita audit` and launch `bash run.sh --demo`.
2. Confirm the window renders without warnings, shows 'Demo (fictional)', contains three events, and selects the first.
3. Search 'httpd', select filters, inspect multi-line contexts; use keyboard-only navigation and screen magnification.
4. Ensure the permissive=1 example says a policy action *would* be denied, never 'blocked'.
5. Save redacted JSON to a temporary local path; verify that target names are not present, and delete the file.
6. Start `bash run.sh` without root. Confirm state from `getenforce`. If `ausearch` is inaccessible, verify a useful error instead of empty success.
7. With appropriate independent administrative audit access, compare specific events against `ausearch` and verify each field, UTC time and interpretation.
8. Exercise empty audit window, unavailable `ausearch`, malformed lines, extended raw records and rapid refresh.
9. Close the app, verify no background helper or daemon remains; inspect local files for no unexpected persisted audit data.
10. Record exact Fedora, GNOME, GTK, Libadwaita, Python and SELinux versions plus observations in the PR or release notes.

## User-reported Fedora observations (2026-11-15)

- **Observed:** `bash run.sh --demo` launches the GTK interface and visibly renders all three fictional records with the first record's context, reasoning, and raw AVC text.
- **Observed:** `bash run.sh` launches in real mode, shows `SELinux: Enforcing`, and explicitly reports denied audit access for the ordinary user.
- **Observed:** `sudo ausearch -m AVC,USER_AVC -ts recent` and `sudo ausearch -m AVC,USER_AVC -ts today` returned `<no matches>` at the time of testing. Distinguish no matching audit records from insufficient permission. Neither proves the absence of any unlogged denial.
- **Not verified:** search/filter interaction, JSON export, all GTK dialog behavior, accessibility, actual populated privileged audit data in GUI, complete Fedora/package version matrix.
- **Follow-up:** test interaction/export with demo, improve the empty-state layout and design authorized least-privilege audit retrieval (never elevate the GUI).

The bounded collector was exercised in the Fedora 45 GNOME Wayland session with SELinux enforcing. Demo loaded three records, and live mode showed explicit audit permission denial with zero rows. Closing the live window while a synthetic audit command was asleep cancelled the query and reaped the child. A populated host audit query was unavailable to the desktop account.

The correlation UI was exercised in the same session with the fictional demo and synthetic records. Checks covered output line provenance, incomplete PATH counts, permissive wording, keyboard focus traversal, an 8 KiB command with a bidi control, resizing, light and dark styles, and clearing evidence when search returns no rows. Fedora's `ausearch` also returned all three supported companion types from a synthetic audit file.

## Future integration tests

Use synthetic audit streams and keep personal raw logs out of fixtures. Correlation tests cover full audit identity, capture and node boundaries, duplicate and malformed lines, quoted field boundaries, incomplete PATH coverage, permissive records, UTC time, and the v1 report boundary. Add integration tests for Polkit authorization denial and helper failure in an isolated Fedora VM. Ordinary CI leaves host SELinux policy intact.

## Test claims

Mark a feature 'unit-tested' only if relevant tests passed; mark 'Fedora-smoke-tested' only if the real UI ran successfully on Fedora. If environment lacks PyGObject, say 'GUI not tested' rather than guessing.
