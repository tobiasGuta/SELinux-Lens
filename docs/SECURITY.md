# Security and threat model

## Security posture (v0.1)

The GTK process is an ordinary unprivileged user process. It calls fixed argv `getenforce` and `ausearch` commands, with no shell and no sudo. It never installs SELinux modules, changes contexts, changes modes, edits booleans, or alters audit configuration. It does not upload audit data, start listeners or persist a local database.

**Audit permissions:** On many Fedora installs, ordinary users cannot query system audit logs. Treat this as an expected protective boundary. The GUI reports that access was denied and exposes --demo for testing. Never instruct users to run the GUI itself as root. If an administrator needs direct logs before a constrained helper exists, inspect them separately with system-supported administration tools, not by weakening SELinux or audit controls.

## Threat actors and data

Attacker-controlled paths, process names, audit fields, malformed log lines, local symlinks, hostile filenames, unexpectedly large audit output, and untrusted diagnostic suggestions are in scope. AVC data can contain sensitive paths, usernames, process identities and security contexts. Some records may contain credential-like data in other fields; do not assume a record is harmless because it is from a local audit daemon.

## Trust boundaries

- Host audit tools -> Python parser: untrusted text, strict parsing and explicit unknowns.
- Parser -> UI: text only, no Pango markup and no shell commands derived from audit data.
- UI -> user-selected file: explicit action; redaction before saving. User owns destination.
- Future UI -> elevated reader: high-risk privilege boundary requiring independent design and review.

## Current safeguards

- Fixed executable names/arguments, `shell=False`, subprocess timeout.
- Strict record selection (AVC/USER_AVC and denial).
- Missing/invalid fields shown as unknown, not invented.
- No implicit policy writes or privilege escalation.
- Memory-only current working set.
- Export redacts the target name/path field and omits full raw records.
- Demo records are explicitly fictional; no host audit access required.

## Current limitations / known risks

- `subprocess.run(capture_output=True)` collects all output **before** the 2 MB size test. This is not an actual process-memory cap. Implement a bounded streaming reader and regression tests before claiming hard caps.
- A user-chosen export path can overwrite an existing file through the regular GTK save dialog; the current implementation uses regular file writes, not hardened atomic writes.
- Report redaction is partial: process names, PIDs, source/target contexts and the report notice remain. Do not publish raw/real reports without review.
- AVC-only records can omit paths or be misleading without related audit records. Correlation is planned.
- Host audit access and tools differ by Fedora configuration and version. See the [Fedora 45 smoke test](TESTING.md#fedora-gnome-smoke-test) for the audit permission result on the development workstation.
- A local attacker who already controls the user session can read in-memory audit data shown to that user; there is no protected secret store.

## Future privileged reader — design constraints

See the [authorized audit access proposal](AUDIT_ACCESS.md) for the comparison of Fedora sources, proposed Polkit contract, disclosure limits, and review tests.

Do not accept arbitrary commands or paths from the UI. Expose a minimal, versioned, read-only D-Bus contract; authorize the caller with Polkit only for explicit narrowly scoped requests; avoid shell, env inheritance and writable code paths; cap request length, output count, time, memory and rate; privilege-drop where possible; defend against race conditions, symlink traversal and caller impersonation. Log sensitive access without leaking records. Prefer established system-supported audit access where it can satisfy least privilege. Threat-model and test before enabling by default.

## Safe remediation philosophy

The tool may offer **inspection steps** and, later, reviewed proposal previews. Never automatically toggle `setenforce`, blanket-allow AVCs, apply `audit2allow`, relabel arbitrary user directories, install custom modules or switch off isolation. An AVC can be expected or caused by application error; a blanket 'fix' could expose data.

If a flaw is found, report it with a minimized synthetic reproducer; do not attach a real user's full audit logs or credentials. Review security-impacting code in PRs.
