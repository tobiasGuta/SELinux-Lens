# SELinux Lens

**Understand what SELinux recorded, why an operation may have been denied, and what to investigate next.**

SELinux Lens is a read-only, native Fedora GNOME app for investigating SELinux AVC / USER_AVC audit events. It uses GTK4 + Libadwaita, calls established Linux audit utilities, and distinguishes **observed audit facts** from **possible explanations**. It is not a policy editor or a vulnerability scanner.

**Current version: v0.1.0 (development preview).** Fedora desktop integration is not yet hardware-tested. The project deliberately has no privileged GUI, automatic SELinux policy modifications, or background service.

## v0.1: implemented

- Native GTK4/Libadwaita two-pane investigation window.
- Read current SELinux mode from `getenforce`.
- Query local audit logs with `ausearch --input-logs -m AVC,USER_AVC -ts recent` (roughly the last ten minutes).
- Parse AVC records, show process, requested permissions, process/target security contexts, object class, audit serial, UTC timestamp, raw record, and permissive flag where present.
- Search and filter AVC records by process, context, permission, target, serial, and enforcing/permissive disposition.
- Evidence-first descriptions and hypotheses, never definitive root-cause claims from a single AVC.
- Explicit failures for unavailable commands, permissions, query timeouts, and oversized output.
- Fictional `--demo` mode for UI review without root or audit access.
- Export JSON report with target names/paths redacted by default; no raw log lines in exports.
- Standard-library tests and CI that do not require root, SELinux or GTK.

### Fedora setup

Use Fedora GNOME, Python >=3.11, GTK4, Libadwaita and PyGObject. Install the system dependencies:

```bash
sudo dnf install python3 python3-gobject gtk4 libadwaita audit
```

Clone and start from the repository checkout (no pip-installed PyGObject necessary):

```bash
git clone https://github.com/tobiasGuta/SELinux-Lens.git
cd SELinux-Lens
bash run.sh --demo
bash run.sh
```

`--demo` displays fictional audit events even on systems without SELinux. Normal launch calls `getenforce` and `ausearch` **without sudo**, so the normal desktop account may be unable to read audit records. This is expected and explicitly reported. Do **not** run the GUI with sudo to work around the limitation. See [docs/SECURITY.md](docs/SECURITY.md).

Run the core test suite:

```bash
make test
make compile
```

These tests run without GTK. GUI smoke tests must currently be performed on a Fedora GNOME desktop.

### Interpret results carefully

An audit AVC with `permissive=0` reports a denied operation. An event with `permissive=1` records a policy denial that may have been **allowed** due to permissive operation. Missing `permissive` information is explicitly unknown. Neither case alone establishes a misconfiguration, an attack, a vulnerability, or the complete cause of a service failure.

The event list shows recent AVC/USER_AVC denials. The detail pane can preview related `SYSCALL`, `PATH`, and `PROCTITLE` records from the same capture and the same full audit identity. It identifies missing records where possible. The AVC command, contexts, and target still come from that individual denial. Audit coverage can be incomplete.

### Export & privacy

The app stores records in memory during the session and does not run a background collector. Export is user-triggered, writes a local JSON report, redacts the target name/path field by default, and omits raw audit lines and related records. **Other fields such as process name, PID, and security contexts remain present** and may reveal sensitive system details: inspect reports before sharing. The Python API offers an explicit `include_paths=True` option for trusted, local workflows, but the GUI does not expose this option in v0.1.

### Project documentation for contributors and Codex

| Document | Use |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Authoritative Codex/agent handoff and coding rules |
| [docs/PRODUCT.md](docs/PRODUCT.md) | Product vision, user stories, scope and success criteria |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, invariants and extension points |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, privilege model, redaction and safe remediation |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Sequenced milestones after v0.1 |
| [docs/TESTING.md](docs/TESTING.md) | Test matrix, manual Fedora validation and quality gates |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Recorded decisions and alternatives |
| [docs/REPORT_FORMAT.md](docs/REPORT_FORMAT.md) | Stable JSON report v1 contract |
| [docs/HANDOFF.md](docs/HANDOFF.md) | Immediate next tasks and known gaps |

## Design principles

1. **Read-only by default.** No `setenforce`, `semanage`, `restorecon`, `audit2allow`, `semodule`, or automatic policy editing.
2. **No root GUI.** Later elevated access, if justified, goes through a constrained, independently reviewed helper with Polkit.
3. **Evidence before inference.** Keep observations, hypotheses and checks visibly separate.
4. **Useful without AI.** Deterministic explanations are auditable; an optional later assistant must not invent policy decisions.
5. **Small and Fedora-native.** Use system APIs and Python GTK4; no Electron, telemetry or mandatory cloud.

## Status and limitations

This is an early development preview, **not a production-ready security control**. Audit access depends on user privileges and host policy; the initial GUI has no authenticated helper. RPM packaging, background events, authoritative SELinux policy analysis, and automated remediation remain outside this preview. The collector bounds audit stdout to 2 MB and stderr to 16 KiB while reading. Report redaction is partial.

Licensed under MIT. Contributions should follow [AGENTS.md](AGENTS.md) and [docs/SECURITY.md](docs/SECURITY.md).
