# Codex / contributor instructions — SELinux Lens

This is the source-of-truth handoff for ongoing work. Read `README.md`, `docs/PRODUCT.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/ROADMAP.md`, and `docs/HANDOFF.md` before changing behavior. Review `docs/AUDIT_ACCESS.md` for authorization changes and `docs/REPORT_FORMAT.md` for export changes. The repository is a **safe, evidence-first Fedora desktop investigation tool**, not a policy editor.

## Product invariant

A user must be able to select a real SELinux AVC denial and answer: what was observed, what is only hypothesized, and what to check next. Never describe an event as proof of an exploit or automatically prescribe permission relaxation. If `permissive=1`, do not call the operation definitely blocked.

## Non-negotiable security rules

- **Never require, encourage, or invoke root for the GTK GUI.** No `sudo python`, `pkexec` launching the whole app, setuid Python, or broad root daemon.
- Never change enforcing mode, disable SELinux, create/enable policy modules, automatically run `audit2allow`, change labels/booleans, or apply changes behind the user's back.
- Keep OS command invocation as fixed-argument, `shell=False` subprocess calls. Treat all audit content, paths, metadata and environment as untrusted.
- No telemetry, uploads, secrets in fixtures, or silent long-term retention. Redact exports by default; document remaining sensitive fields.
- Future privileged audit reader must have constrained interfaces, no shell interpretation, fixed allowlisted operations, Polkit authorization, bounded output/time, and threat-model review before merge. Prefer a system-supported read-only mechanism where available.
- Never fabricate evidence: a parsed record is not correlated audit context; do not infer the root cause from `scontext` and `tcontext` alone.
- Preserve accessibility: keyboard navigation, visible error states, sensible contrast, reduced motion, and text selection where useful.

## Architecture boundaries

- `models.py`: typed domain objects only; no GTK or system access.
- `audit.py`: raw collection and parser; bounded, no privilege elevation; no GTK.
- `explain.py`: deterministic observations/hypotheses/checks, not advice to weaken policy.
- `report.py`: versioned export and redaction; independent of GUI.
- `demo.py`: clearly fictional, stable evidence fixtures; no host data.
- `gui.py`: presentation and event wiring only; subprocess work off the GTK main thread.
- `__main__.py`: CLI parsing and lazy GTK import; `--help` works without GTK.

Add new functions to the appropriate layer. Preserve dependency direction: GUI -> domain/services; domain/services never import GUI.

## Development workflow

1. Make the smallest independently testable change. Update relevant docs and tests in the same PR.
2. Run `make test` and `make compile`. Do not claim GUI testing unless actually run on Fedora GNOME.
3. For parser changes, add fixture-based tests covering malformed, adversarial, incomplete and permissive records.
4. For GUI changes, test keyboard navigation, long lines, empty states, failed audit access, --demo, and export on Fedora.
5. Include a security-impact statement for changes touching subprocess, filesystem, privilege, policy logic or export.
6. Prefer feature branches and PR review; don't force-push main. Document what was verified vs. merely reasoned about.
7. Do not overwrite or discard user changes. Check branch and working tree state before editing.
8. Use the repository's configured Git identity. Keep commit and pull request text focused on the engineering changes.

## Near-term priorities

P0: validate the authorized audit reader design in an isolated Fedora GNOME VM and keep the GTK process unprivileged. P0: finish real-device validation for portal export, physical keyboard accessibility, and populated audit queries. P1: improve audit coverage indicators and preserve provenance through grouping and policy/context inspection. P2: distribution, RPM, desktop files and integration testing. Detailed milestones and acceptance tests live in `docs/ROADMAP.md`.

## Completion criteria for any milestone

Behavior implemented; tests passing; security consequences assessed; docs/roadmap updated; Fedora desktop manually exercised for UI changes; accessible failure paths confirmed; report formats backward-compatible or explicitly versioned. Never claim work is complete solely because code compiles.
