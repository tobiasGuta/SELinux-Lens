# Testing and verification

## Developer checks (without root or GNOME)

```bash
make compile
make test
PYTHONPATH=src python3 -m selinux_lens --help
PYTHONPATH=src python3 -m selinux_lens --version
```

Unit tests exercise AVC parsing, record ordering, permissive semantics, dependency injection, missing commands, permission denial, post-capture size rejection, export redaction and deterministic explanations. Core modules intentionally import no GTK.

GitHub Actions runs compile/tests on Python 3.11 and 3.13. Passing these checks **does not validate runtime GTK compatibility, SELinux policy behavior, audit access or safe use on a live workstation**.

## Fedora GNOME manual checklist (not yet completed)

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

## Future integration tests

Use synthetic audit streams; never commit personal raw logs. Add tests for serial correlation, PATH/PROCTITLE association, duplicate records, truncated lines, adversarial string content, huge output streams, cancellation, Polkit authorization denial and helper failure. Use isolated Fedora VM tests for privileged collector work; never mutate host SELinux policy as part of ordinary CI.

## Test claims

Mark a feature 'unit-tested' only if relevant tests passed; mark 'Fedora-smoke-tested' only if the real UI ran successfully on Fedora. If environment lacks PyGObject, say 'GUI not tested' rather than guessing.
