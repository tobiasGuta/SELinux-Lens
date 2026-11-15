# Security and threat model

## Security posture (v0.1)

The GTK process is an ordinary unprivileged user process. It calls fixed argv `getenforce` and `ausearch` commands, with no shell and no sudo. It never installs SELinux modules, changes contexts, changes modes, edits booleans, or alters audit configuration. It does not upload audit data, start listeners or persist a local database.

**Audit permissions:** On many Fedora installs, ordinary users cannot query system audit logs. Treat this as an expected protective boundary. The GUI reports that access was denied and exposes --demo for testing. Never instruct users to run the GUI itself as root. If an administrator needs direct logs before a constrained helper exists, inspect them separately with system-supported administration tools, not by weakening SELinux or audit controls.

## Threat actors and data

Attacker-controlled paths, process names, audit fields, malformed log lines, local symlinks, hostile filenames, unexpectedly large audit output, and untrusted diagnostic suggestions are in scope. AVC data can contain sensitive paths, usernames, process identities and security contexts. Some records may contain credential-like data in other fields; do not assume a record is harmless because it is from a local audit daemon.

## Trust boundaries

- Host audit tools -> Python parser: untrusted text, strict parsing and explicit unknowns.
- Parser -> UI: text only, no Pango markup and no shell commands derived from audit data.
- UI -> user-selected file: explicit action and shareable v2 serialization. The app opens each destination directory component without following symlinks and publishes a finished, previously unnamed inode under a new name.
- Future UI -> elevated reader: high-risk privilege boundary requiring independent design and review.

## Current safeguards

- Fixed absolute executable paths and arguments, `shell=False`, closed stdin, and a fixed locale with no inherited environment variables.
- Separate stdout and stderr capture limits, deadlines, and cancellation when the window closes. A byte cap, cancellation or subprocess failure discards captured output. If the parsed record count exceeds the display limit, the app shows the newest complete records and reports the limit. The byte limits apply to captured data in the parent. The child process retains the OS limits of the desktop session.
- Strict record selection (AVC/USER_AVC and denial).
- Companion previews require a supported type and matching node, timestamp and serial within one capture. They do not supply AVC path or process fields. The UI escapes control characters and bounds rendered previews.
- Missing/invalid fields shown as unknown, not invented.
- The desktop entry point checks for effective UID zero before initializing GTK. Collection has no implicit policy writes or privilege escalation.
- Memory-only current working set.
- Desktop export omits identifying fields, diagnostic text and raw or companion records. The finished file uses mode 0600 or stricter. An existing file or symlink at the chosen name is preserved.
- Demo records are explicitly fictional; no host audit access required.

## Current limitations / known risks

- The v1 Python report API retains process names, PIDs, contexts and the report notice. Use the GUI's v2 export when sharing a summary. Atomic publication requires a local filesystem with Linux unnamed temporary file and hard-link support, plus procfs for publishing the open file as the desktop user.
- Audit coverage can be incomplete. Related evidence previews may contain sensitive identities, paths, and encoded command arguments. The previews are collapsed by default and omitted from reports.
- Host audit access and tools differ by Fedora configuration and version. See the [Fedora 45 smoke test](TESTING.md#fedora-gnome-smoke-test) for the audit permission result on the development workstation.
- A local attacker who already controls the user session can read in-memory audit data shown to that user; there is no protected secret store.

## Future privileged reader — design constraints

See the [authorized audit access proposal](AUDIT_ACCESS.md) for the comparison of Fedora sources, proposed Polkit contract, disclosure limits, and review tests.

The draft treats direct logind membership and administrator consent as independent requirements. D-Bus peer credentials pin a process identity. A Polkit challenge or UID display-session fallback cannot attest the origin of a request within a particular active local seat session. Hold the original session binding through authorization and collection. Concurrent same-UID sessions, loss of eligibility, bus disconnect, logind restart and descriptor delegation are explicit review cases. Keep any artifact handoff under the administrator's deliberate control and retain a clear source label in the unprivileged application. [VM observations and remaining validation](FEDORA_VM_VALIDATION.md)

Do not accept arbitrary commands or paths from the UI. Expose a minimal, versioned, read-only D-Bus contract; authorize the caller with Polkit only for explicit narrowly scoped requests; avoid shell, env inheritance and writable code paths; cap request length, output count, time, memory and rate; privilege-drop where possible; defend against race conditions, symlink traversal and caller impersonation. Log sensitive access without leaking records. Prefer established system-supported audit access where it can satisfy least privilege. Threat-model and test before enabling by default.

## Safe remediation philosophy

The tool may offer **inspection steps** and, later, reviewed proposal previews. Never automatically toggle `setenforce`, blanket-allow AVCs, apply `audit2allow`, relabel arbitrary user directories, install custom modules or switch off isolation. An AVC can be expected or caused by application error; a blanket 'fix' could expose data.

If a flaw is found, report it with a minimized synthetic reproducer; do not attach a real user's full audit logs or credentials. Review security-impacting code in PRs.
