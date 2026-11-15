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

## Fedora GNOME smoke test

On 2026-11-15 the application ran in a Fedora Workstation 45 GNOME Wayland session, with GNOME Shell 51.1, GTK 4.24.1, Libadwaita 1.10.0, PyGObject 3.58.1, Python 3.15.2, audit 4.2.1, libselinux 3.11 and targeted policy 45.24. The desktop account ran as UID 1000 and already belonged to `wheel`. SELinux was enforcing.

- The separate demo launch showed three fictional records while a normal instance was open. Search, empty search results, disposition filters, selection, and both permissive messages were checked using AT-SPI and live GTK widget actions. GTK focus traversal reached the filter from search.
- An 8 KiB unbroken synthetic value initially expanded the window to roughly 70,000 pixels wide. After enabling word/character wrapping, the test window resized to 820 × 540. Light and dark Libadwaita modes both activated.
- `Gtk.FileChooserNative` save and cancel passed using GTK's in-process chooser backend. The saved v1 report had three redacted targets and omitted raw lines. An injected write error produced the visible export failure. The desktop portal chooser path was not verified.
- Normal-mode collection showed `Enforcing`, explicit audit access denial, zero rows, and a disabled export button. `ausearch` returned permission denied for both its configuration and its audit log on this account.
- GTK emitted a `GtkBox` minimum/natural width measurement warning. Physical keyboard and magnifier testing, portal-backed export, and comparison against real records with separately authorized audit access remain outstanding.

## Fedora GNOME manual checklist

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

## Future integration tests

Use synthetic audit streams and keep personal raw logs out of fixtures. Add tests for serial correlation, PATH/PROCTITLE association, duplicate records, truncated lines, control characters, Polkit authorization denial and helper failure. Use isolated Fedora VM tests for privileged collector work. Ordinary CI leaves host SELinux policy intact.

## Test claims

Mark a feature 'unit-tested' only if relevant tests passed; mark 'Fedora-smoke-tested' only if the real UI ran successfully on Fedora. If environment lacks PyGObject, say 'GUI not tested' rather than guessing.
