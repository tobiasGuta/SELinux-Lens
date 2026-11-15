# Product roadmap and implementation phases

The roadmap is a plan, **not a list of implemented features**. Prioritize safety/correctness before visual polish.

## v0.1 — Read-only foundation (initial draft implementation)

[x] Native GTK4/Libadwaita UI, search/filter and detail view  
[x] Parse recent AVC and USER_AVC records, preserving unknowns  
[x] Clearly distinguish permissive flag, observations and hypotheses  
[x] Non-root fixed-argv audit command invocation and degraded states  
[x] Fictional demo mode, redacted JSON report, unit tests/CI  
[ ] Complete Fedora GNOME real-device smoke testing. [Fedora 45 results and remaining checks](TESTING.md#fedora-gnome-smoke-test)\
[ ] Audit access tested for ordinary user vs administrator on supported Fedora versions

## v0.1.1 — Production-quality input boundary

- Replace post-capture truncation with **bounded streaming** stdout/stderr collection, process deadline, resource limits and clean cancellation; test high-volume/hostile outputs.
- Validate output encoding and control characters; cap individual line length and UI rendering cost.
- Tighten unknown mode, ausearch exit-code and stderr/no-record classification on Fedora.
- Improve export redaction (contexts, commands, paths, optional field selection), atomic write, overwrite confirmation and metadata minimization.
- Add deterministic corpus of SELinux AVC shapes (host variations, malformed, duplicate, permissive, missing fields); protect against false interpretations.

## v0.2 — Reliable audit access and correlation

Compare system-supported sources and review a minimal, read-only interface before implementing privileged access. [Authorized audit access proposal](AUDIT_ACCESS.md)

- Design a minimal audited **read-only** privileged data source (Polkit if truly necessary); no root GUI.
- Correlate same-serial AVC/SYSCALL/PATH/PROCTITLE, explicit evidence provenance and incomplete-record handling.
- Separate 'no events', 'no permission', 'SELinux disabled', 'audit disabled', 'collection timed out', 'partial evidence'.
- Add time-window controls, pagination, grouping and testable domain models.
- Validate on Fedora GNOME versions with SELinux enforcing.

## v0.3 — Policy and context intelligence

- Read-only default-label inspection, process/file contexts, file context patterns, installed booleans and policy decisions.
- Cite authoritative local evidence for each explanation; explicitly indicate uncertainty.
- Guided checks for mislabeling vs policy vs application configuration.
- No one-click broad policy modifications or automatic 'audit2allow'.

## v0.4 — Investigation workspace

- Live follow mode with backpressure and service-oriented case grouping.
- Timeline, saved searches, filters, keyboard navigation and accessible detail comparisons.
- Optional explicit local case retention with limits and deletion controls; no silent database.
- Versioned JSON/Markdown reports with granular redaction and provenance.

## v0.5 — Distribution and quality

- Fedora RPM build and signed-release strategy, desktop file, AppStream, icon and GNOME polish.
- Automated Fedora container/core integration where feasible, desktop smoke testing on Fedora VMs.
- Translation-friendly UX, accessibility evaluation, supported Fedora version matrix.
- Benchmark resource consumption and review privilege isolation.

## Later ideas (only after proven need)

ServiceForge integration via stable local API; side-by-side policy diff; trusted rule-reference browser; optional local-only explanatory model explicitly lower-confidence than deterministic evidence. No arbitrary policy patch automation.

## Milestone release gate

For each milestone: tests pass, docs updated, hostile-input and degraded-state tests pass, privilege model reviewed, actual Fedora GNOME smoke test documented, and repository release notes clearly distinguish shipped functionality from planned work.
