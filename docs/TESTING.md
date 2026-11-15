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
- The initial run reproduced a GTK width measurement warning in the container around the notice and split view. Moving the notice and separator into the existing toolbar eliminated the warning in repeated search, resize, theme, and chooser checks. Physical keyboard and magnifier testing, portal-backed export, and comparison against real records with separately authorized audit access remain outstanding.

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

The correlation UI was exercised in the same session with the fictional demo and synthetic records. Checks covered output line provenance, incomplete PATH counts, permissive wording, keyboard focus traversal, an 8 KiB command with a bidi control, resizing, light and dark styles, and clearing evidence when search returns no rows. Fedora's `ausearch` also returned all three supported companion types from a synthetic audit file.

## Investigation states and shareable export

Fedora 45 GNOME showed distinct status pages for real audit permission denial, a simulated successful empty query and a simulated query failure. Search with no results used a separate filter message. The demo and synthetic evidence checks exercised focus traversal, an 8 KiB value, incomplete PATH evidence, permissive wording, resizing and light and dark appearance.

The GTK in-process native chooser saved a shareable v2 report and handled cancel and an injected write failure. Automated tests verify the v1 report API, v2 redaction, file permissions, existing files and symlinks, failure cleanup, concurrent exports, and the root-launch guard. Portal-backed chooser and physical keyboard testing remain open.

### User-observed v0.1.1 candidate check

- `git pull --ff-only` reported that the local checkout was up to date. `make test` passed all 38 tests on that checkout.
- `bash run.sh --demo` showed three fictional AVCs. Detail and related-record views rendered, and the PATH indicator showed incomplete evidence.
- `bash run.sh` ran under the desktop account with SELinux enforcing. The centered **Audit access required** page appeared with zero loaded records and a disabled **Export JSON** button.
- The inspected demo export used `selinux-lens-report/v2` with three fictional events. Its event objects contained only permissions, target class and permissive disposition. The report contained no raw audit messages, paths, PIDs, process names or security contexts.

Those manual checks covered the visible app and exported contents. File mode, atomic publication, the portal-backed chooser and physical keyboard navigation were outside their scope. The stabilization tests separately exercised no-overwrite and atomic publication behavior, ancestor symlink rejection, and a directory rename during export. A repeat in-process chooser test on Fedora 45 checked the saved file's mode independently. The updated collector and GUI were also checked with simulated malformed, incomplete and unavailable capture outcomes.

## Future integration tests

The uninstalled reader has a separate private-bus suite. On Fedora, install the standard Gio Python bindings and `dbus-run-session`, then use `make test-prototype`. The suite checks peer credential pinning, absent interaction flags, malformed calls, ineligible and denied callers, disconnect cancellation, concurrency, rate limits, evidence redaction and serialized D-Bus reply size. It uses synthetic evidence and simulated session and Polkit outcomes. The suite also passed in an isolated rootless Fedora 45 container.

The enforcing KVM component probes exercised real D-Bus credentials, logind, Polkit decisions and `ausearch` with a synthetic file. They exposed a GNOME session resolution gap. The candidate-service integration tests still require a scoped service identity, activation, resource limits and confinement. [VM setup, observations and remaining tests](FEDORA_VM_VALIDATION.md)

Use synthetic audit streams and keep personal raw logs out of fixtures. Correlation tests cover full audit identity, capture and node boundaries, duplicate and malformed lines, quoted field boundaries, incomplete PATH coverage, permissive records, UTC time, and the v1 report boundary. Add integration tests for Polkit authorization denial and helper failure in an isolated Fedora VM. Ordinary CI leaves host SELinux policy intact.

## Test claims

Mark a feature 'unit-tested' only if relevant tests passed; mark 'Fedora-smoke-tested' only if the real UI ran successfully on Fedora. If environment lacks PyGObject, say 'GUI not tested' rather than guessing.
