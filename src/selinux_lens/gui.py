"""GTK4/Libadwaita investigation UI; intentionally contains no write controls."""

from __future__ import annotations

import threading
from pathlib import Path
from unicodedata import category

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Pango  # noqa: E402

from .audit import load_recent
from .demo import demo_snapshot
from .explain import interpret
from .models import AuditEvidence, CollectionStatus, Denial, Snapshot
from .report import write_shareable_report

_CONTROL_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}
_RELATED_PREVIEW_COUNT = 12
_EMPTY_TITLES = {
    CollectionStatus.PERMISSION_DENIED: "Audit access required",
    CollectionStatus.NO_MATCHES: "No recent AVC denials",
    CollectionStatus.UNAVAILABLE: "Audit source unavailable",
    CollectionStatus.FAILED: "Audit query failed",
    CollectionStatus.TIMED_OUT: "Audit query timed out",
    CollectionStatus.OUTPUT_LIMIT: "Audit output limit reached",
    CollectionStatus.CANCELLED: "Audit query cancelled",
    CollectionStatus.INCOMPLETE: "Audit evidence incomplete",
    CollectionStatus.MALFORMED: "Audit output could not be read",
}


def audit_preview(text: str, limit: int = 4096) -> str:
    """Expose control characters and bound the amount of text GTK lays out."""
    escaped = "".join(
        (f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}")
        if category(char) in _CONTROL_CATEGORIES else char
        for char in text[:limit]
    )
    if len(text) > limit or len(escaped) > limit:
        return escaped[:limit] + "… [preview shortened]"
    return escaped


def evidence_summary(event: Denial, evidence: AuditEvidence) -> str:
    node = audit_preview(evidence.node, 128) if evidence.node else "not recorded"
    lines = [
        f"Audit ID {evidence.epoch}:{event.event_id} • Node {node}",
        f"Denial record at output line {evidence.line_number}",
    ]
    kinds = {record.kind for record in evidence.related}
    missing = [kind for kind in ("SYSCALL", "PATH", "PROCTITLE") if kind not in kinds]
    if evidence.expected_paths == 0 and "PATH" in missing:
        missing.remove("PATH")
    if missing:
        lines.append("No usable records of these types: " + ", ".join(missing))
    if evidence.expected_paths is not None:
        path_items = {record.path_item for record in evidence.related if record.kind == "PATH"}
        present = sum(item is not None and item < evidence.expected_paths for item in path_items)
        lines.append(f"PATH items observed: {present} of {evidence.expected_paths} reported by SYSCALL")
    return "\n".join(lines)


def label(text: str = "", *, style: str = "", selectable: bool = False) -> Gtk.Label:
    widget = Gtk.Label(label=text)
    widget.set_xalign(0)
    widget.set_wrap(True)
    widget.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    widget.set_selectable(selectable)
    if style:
        widget.add_css_class(style)
    return widget


def column(spacing: int = 12) -> Gtk.Box:
    return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)


class LensWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application, *, demo: bool) -> None:
        super().__init__(application=app, title="SELinux Lens")
        self.set_default_size(1100, 740)
        self._demo = demo
        self._busy = False
        self._snapshot = Snapshot("Unknown", (), "ausearch")
        self._visible: list[Denial] = []
        self._export_dialog: Gtk.FileChooserNative | None = None
        self._exporting = False

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle.new("SELinux Lens", "Read-only AVC investigations"))
        self.mode_label = label("Checking SELinux…", style="dim-label")
        header.pack_start(self.mode_label)

        self.refresh_button = Gtk.Button(label="Refresh")
        self.refresh_button.connect("clicked", self._refresh_clicked)
        header.pack_end(self.refresh_button)

        self.export_button = Gtk.Button(label="Export JSON")
        self.export_button.set_sensitive(False)
        self.export_button.connect("clicked", self._export_clicked)
        header.pack_end(self.export_button)
        toolbar.add_top_bar(header)

        self.notice_label = label(style="dim-label")
        self.notice_label.set_visible(False)
        self.notice_label.set_margin_start(18)
        self.notice_label.set_margin_end(18)
        self.notice_label.set_margin_top(10)
        self.notice_label.set_margin_bottom(10)
        toolbar.add_top_bar(self.notice_label)
        toolbar.add_top_bar(Gtk.Separator())

        content = Gtk.Paned.new(Gtk.Orientation.HORIZONTAL)
        content.set_position(365)
        content.set_wide_handle(True)

        left = column()
        left.set_margin_start(18)
        left.set_margin_end(14)
        left.set_margin_top(18)
        left.set_margin_bottom(18)
        left.append(label("Recent AVC denials", style="title-3"))
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search process, type, permission…")
        self.search.connect("search-changed", self._filters_changed)
        left.append(self.search)

        self.filter = Gtk.DropDown.new_from_strings(
            ["All records", "Enforcing records", "Permissive records", "Unknown disposition"]
        )
        self.filter.connect("notify::selected", self._filters_changed)
        left.append(self.filter)

        self.count_label = label("", style="dim-label")
        left.append(self.count_label)
        self.event_list = Gtk.ListBox()
        self.event_list.add_css_class("boxed-list")
        self.event_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.event_list.connect("row-selected", self._selected)
        left_scroll = Gtk.ScrolledWindow()
        left_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        left_scroll.set_vexpand(True)
        left_scroll.set_child(self.event_list)
        left.append(left_scroll)
        content.set_start_child(left)
        content.set_resize_start_child(True)
        content.set_shrink_start_child(False)

        details = column(16)
        details.set_margin_start(22)
        details.set_margin_end(22)
        details.set_margin_top(22)
        details.set_margin_bottom(22)

        self.details_title = label(style="title-2")
        details.append(self.details_title)
        self.details_meta = label("", style="dim-label", selectable=True)
        details.append(self.details_meta)

        details.append(label("Observed facts", style="heading"))
        self.facts_label = label(selectable=True)
        details.append(self.facts_label)

        details.append(label("Security contexts", style="heading"))
        self.context_label = label("", style="monospace", selectable=True)
        details.append(self.context_label)

        details.append(label("Possible explanations — not confirmed", style="heading"))
        self.hypotheses_label = label("", selectable=True)
        details.append(self.hypotheses_label)

        details.append(label("Suggested next checks", style="heading"))
        self.checks_label = label("", selectable=True)
        details.append(self.checks_label)

        details.append(label("Original AVC record preview", style="heading"))
        self.raw_label = label("", style="monospace", selectable=True)
        details.append(self.raw_label)

        self.evidence_box = column(8)
        self.evidence_box.append(label("Related audit records", style="heading"))
        self.evidence_summary = label("", selectable=True)
        self.evidence_box.append(self.evidence_summary)
        self.related_expander = Gtk.Expander(label="Show record previews")
        self.related_records = label("", style="monospace", selectable=True)
        self.related_expander.set_child(self.related_records)
        self.evidence_box.append(self.related_expander)
        details.append(self.evidence_box)
        details.append(label(
            "SELinux Lens never generates or applies policy changes. "
            "Correlate the complete audit event before drawing conclusions.",
            style="dim-label",
        ))

        self._details_stack = Gtk.Stack(hhomogeneous=False, vhomogeneous=False)
        self._status_page = Adw.StatusPage()
        self._status_page.add_css_class("compact")
        self._details_stack.add_named(self._status_page, "status")
        self._details_stack.add_named(details, "event")

        right_scroll = Gtk.ScrolledWindow()
        right_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        right_scroll.set_child(self._details_stack)
        content.set_end_child(right_scroll)
        content.set_resize_end_child(True)
        content.set_shrink_end_child(False)
        toolbar.set_content(content)
        self.set_content(toolbar)
        self._cancel_collection = threading.Event()
        self.connect("close-request", self._close_requested)
        self._refresh()

    def _close_requested(self, _window: Gtk.Window) -> bool:
        self._cancel_collection.set()
        return False

    def _refresh_clicked(self, _button: Gtk.Button) -> None:
        self._refresh()

    def _refresh(self) -> None:
        if self._busy:
            return
        if self._demo:
            self._finish(demo_snapshot())
            return
        self._busy = True
        self.refresh_button.set_sensitive(False)
        self.notice_label.set_text("Reading the recent audit window…")
        if not self._snapshot.events:
            self._show_empty_state()

        def work() -> None:
            snapshot = load_recent(cancel=self._cancel_collection)
            if not self._cancel_collection.is_set():
                GLib.idle_add(self._finish, snapshot)

        # Allow cleanup and child reaping if the application exits mid-query.
        threading.Thread(target=work, name="selinux-lens-audit").start()

    def _finish(self, snapshot: Snapshot) -> bool:
        if self._cancel_collection.is_set():
            return GLib.SOURCE_REMOVE
        self._busy = False
        self.refresh_button.set_sensitive(True)
        self._snapshot = snapshot
        self.mode_label.set_text(f"SELinux: {snapshot.mode}")
        text = snapshot.notice or f"Loaded {len(snapshot.events)} recent AVC records."
        self.notice_label.set_text(text)
        self.notice_label.set_visible(bool(snapshot.events))
        self.export_button.set_sensitive(bool(snapshot.events) and not self._exporting)
        self._update_list()
        return GLib.SOURCE_REMOVE

    def _filters_changed(self, *_args: object) -> None:
        self._update_list()

    def _update_list(self) -> None:
        query = self.search.get_text().strip().casefold()
        choice = self.filter.get_selected()
        self._visible = [
            event
            for event in self._snapshot.events
            if (
                (choice == 0)
                or (choice == 1 and event.permissive is False)
                or (choice == 2 and event.permissive is True)
                or (choice == 3 and event.permissive is None)
            )
            and query in " ".join(
                (
                    event.command, event.permissions, event.source_context,
                    event.target_context, event.target_class, event.target,
                    event.event_id,
                )
            ).casefold()
        ]
        while row := self.event_list.get_row_at_index(0):
            self.event_list.remove(row)
        for event in self._visible:
            row = Gtk.ListBoxRow()
            body = column(4)
            body.set_margin_start(10)
            body.set_margin_end(10)
            body.set_margin_top(9)
            body.set_margin_bottom(9)
            body.append(label(audit_preview(event.headline, 160), style="heading"))
            body.append(label(
                f"#{event.event_id} • {event.timestamp_utc} • "
                + ("Permissive" if event.permissive is True else
                   "Denied" if event.permissive is False else "Disposition unknown"),
                style="dim-label",
            ))
            row.set_child(body)
            self.event_list.append(row)
        self.count_label.set_text(
            f"{len(self._visible)} shown / {len(self._snapshot.events)} loaded"
        )
        if self._visible:
            self.event_list.select_row(self.event_list.get_row_at_index(0))
        else:
            self._selected(self.event_list, None)

    def _show_empty_state(self) -> None:
        snapshot = self._snapshot
        if snapshot.events and self._visible:
            title = "Select a denial"
            description = "Choose a record to see its evidence and suggested checks."
        elif snapshot.events:
            title = "No records match your filters"
            description = "Change the search or disposition filter to see loaded records."
        elif self._busy:
            title = "Reading recent audit records"
            description = ""
        else:
            title = _EMPTY_TITLES.get(snapshot.status, "No audit records loaded")
            description = snapshot.notice
            if snapshot.status == CollectionStatus.PERMISSION_DENIED:
                description = (
                    "Your account cannot read the system audit logs. "
                    "Open the fictional demo to explore the investigation view."
                )
            elif snapshot.status == CollectionStatus.NO_MATCHES:
                description = "The query found no denials in the recent audit window."
                if snapshot.mode == "Disabled":
                    description += " SELinux is currently disabled."
        self._status_page.set_title(title)
        self._status_page.set_description(description)
        self._details_stack.set_visible_child_name("status")

    def _selected(
        self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None
    ) -> None:
        if row is None:
            for widget in (
                self.details_title, self.details_meta, self.facts_label, self.context_label,
                self.hypotheses_label, self.checks_label, self.raw_label,
            ):
                widget.set_text("")
            self._show_evidence(None)
            self._show_empty_state()
            return
        index = row.get_index()
        if index < 0 or index >= len(self._visible):
            return
        event = self._visible[index]
        explanation = interpret(event)
        self.details_title.set_text(audit_preview(event.headline, 512))
        self.details_meta.set_text(
            f"Audit serial {event.event_id} • UTC {event.timestamp_utc}"
            + (f" • PID {audit_preview(event.pid, 80)}" if event.pid else "")
        )
        self.facts_label.set_text(audit_preview(explanation.observed))
        self.context_label.set_text(
            f"Source: {audit_preview(event.source_context or '(missing)', 1024)}\n"
            f"Target: {audit_preview(event.target_context or '(missing)', 1024)}\n"
            f"Object class: {audit_preview(event.target_class or '(missing)', 256)}\n"
            f"Target name/path: {audit_preview(event.target or '(not present in AVC)', 1024)}"
        )
        self.hypotheses_label.set_text(
            "\n\n".join("• " + item for item in explanation.possible_explanations)
        )
        self.checks_label.set_text(
            "\n".join("• " + item for item in explanation.next_checks)
        )
        self.raw_label.set_text(audit_preview(event.raw))
        self._show_evidence(event)
        self._details_stack.set_visible_child_name("event")

    def _show_evidence(self, event: Denial | None) -> None:
        evidence = event.evidence if event is not None else None
        self.evidence_box.set_visible(evidence is not None)
        if event is None or evidence is None:
            self.evidence_summary.set_text("")
            self.related_records.set_text("")
            self.related_expander.set_expanded(False)
            return
        self.evidence_summary.set_text(evidence_summary(event, evidence))
        self.related_expander.set_visible(bool(evidence.related))
        self.related_expander.set_expanded(False)
        previews = [
            f"{record.kind} • Output line {record.line_number}\n{audit_preview(record.raw, 512)}"
            for record in evidence.related[:_RELATED_PREVIEW_COUNT]
        ]
        omitted = len(evidence.related) - len(previews)
        if omitted:
            previews.append(f"{omitted} additional related records omitted from the preview.")
        self.related_records.set_text("\n\n".join(previews))

    def _export_clicked(self, _button: Gtk.Button) -> None:
        if self._export_dialog is not None or self._exporting or not self._snapshot.events:
            return
        snapshot = self._snapshot
        dialog = Gtk.FileChooserNative.new(
            "Export SELinux Lens report", self,
            Gtk.FileChooserAction.SAVE, "Save", "Cancel"
        )
        dialog.set_modal(True)
        dialog.set_current_name("selinux-lens-report.json")
        self._export_dialog = dialog

        def response(chooser: Gtk.FileChooserNative, result: int) -> None:
            try:
                if result == Gtk.ResponseType.ACCEPT:
                    chosen = chooser.get_file()
                    path = chosen.get_path() if chosen is not None else None
                    if path is None:
                        self._show_export_notice("Choose a local folder for the report.")
                    else:
                        self._save_report(snapshot, Path(path))
            finally:
                self._export_dialog = None
                chooser.destroy()

        dialog.connect("response", response)
        dialog.show()

    def _show_export_notice(self, notice: str) -> None:
        self.notice_label.set_text(notice)
        self.notice_label.set_visible(True)

    def _save_report(self, snapshot: Snapshot, destination: Path) -> None:
        self._exporting = True
        self.export_button.set_sensitive(False)
        self._show_export_notice("Saving shareable report…")

        def work() -> None:
            try:
                write_shareable_report(snapshot, destination)
            except FileExistsError:
                notice = "A file already has that name. Choose a new name for the report."
            except OSError:
                notice = "Could not save the report to the chosen destination."
            else:
                notice = "Shareable report saved."
            GLib.idle_add(self._finish_export, notice)

        threading.Thread(target=work, name="selinux-lens-export").start()

    def _finish_export(self, notice: str) -> bool:
        self._exporting = False
        if not self._cancel_collection.is_set():
            self.export_button.set_sensitive(bool(self._snapshot.events))
            self._show_export_notice(notice)
        return GLib.SOURCE_REMOVE


class LensApplication(Adw.Application):
    def __init__(self, *, demo: bool) -> None:
        super().__init__(
            application_id=(
                "io.github.tobiasguta.SELinuxLens.Demo" if demo
                else "io.github.tobiasguta.SELinuxLens"
            ),
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.demo = demo
        self.connect("activate", self._activate)

    def _activate(self, _app: Adw.Application) -> None:
        window = self.props.active_window
        if window is None:
            window = LensWindow(self, demo=self.demo)
        window.present()


def launch(*, demo: bool = False) -> int:
    return LensApplication(demo=demo).run([])
