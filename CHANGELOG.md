# Changelog

## v0.1.1 — 2026-11-15

Development preview for Fedora 45 Workstation on GNOME Wayland.

- Added bounded audit subprocess capture, deadlines, cancellation on close and child cleanup.
- Correlated AVC, SYSCALL, PATH and PROCTITLE evidence by full audit identity within a capture. The detail view shows output provenance and incomplete PATH coverage.
- Added distinct audit permission, missing source, malformed output, incomplete evidence, empty results and error states. The GUI entry point refuses a root launch before loading GTK.
- Added shareable v2 JSON export with identifying data omitted. Exports use private file permissions and publish a complete report at a new filename. Existing files and symlinks are preserved. The detailed v1 Python API remains available.
- Fixed demo launch alongside live mode, long-value wrapping and a GTK sizing warning.

Run from the tagged source under a regular desktop account. Audit access depends on existing log permissions, and demo mode uses fictional records. Export requires a direct local path on a filesystem with Linux unnamed temporary file and hard-link support. The development preview ships without a privileged audit reader. Portal-backed export, physical keyboard and magnifier checks, and comparison against populated live audit logs remain open.

Verification includes 41 core tests, Python compilation, GitHub CI on Python 3.11 and 3.13, Fedora GNOME smoke tests and inspection of the saved demo report. [Installation](README.md#fedora-setup) · [Testing](docs/TESTING.md) · [Security](docs/SECURITY.md)
