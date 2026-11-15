"""GTK4/Libadwaita investigation UI; intentionally contains no write controls."""

from __future__ import annotations

import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Pango  # noqa: E402

from . import __version__
from .audit import load_recent
from .demo import demo_snapshot
from .explain import interpret
from .models import Denial, Snapshot
from .report import serialize_report


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

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.notice_label = label(
            "Reports redact target paths by default. All investigations remain in memory.",
            style="dim-label",
        )
        self.notice_label.set_margin_start(18)
        self.notice_label.set_margin_end(18)
        self.notice_label.set_margin_top(10)
        self.notice_label.set_margin_bottom(10)
        outer.append(self.notice_label)
        outer.append(Gtk.Separator())

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

        self.details_title = label("Select a denial to investigate", style="title-2")
        details.append(self.details_title)
        self.details_meta = label("", style="dim-label", selectable=True)
        details.append(self.details_meta)

        details.append(label("Observed facts", style="heading"))
        self.facts_label = label(
            "Facts extracted from audit records will appear here.", selectable=True
        )
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

        details.append(label("Original AVC record", style="heading"))
        self.raw_label = label("", style="monospace", selectable=True)
        details.append(self.raw_label)
        details.append(label(
            "SELinux Lens never generates or applies policy changes. "
            "Correlate the complete audit event before drawing conclusions.",
            style="dim-label",
        ))

        right_scroll = Gtk.ScrolledWindow()
        right_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        right_scroll.set_child(details)
        content.set_end_child(right_scroll)
        content.set_resize_end_child(True)
        content.set_shrink_end_child(False)
        outer.append(content)
        toolbar.set_content(outer)
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
        self.export_button.set_sensitive(bool(snapshot.events))
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
            body.append(label(event.headline, style="heading"))
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

    def _selected(
        self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None
    ) -> None:
        if row is None:
            self.details_title.set_text("No denial selected")
            self.details_meta.set_text("Adjust filters, refresh, or run --demo.")
            for widget in (
                self.facts_label, self.context_label, self.hypotheses_label,
                self.checks_label, self.raw_label,
            ):
                widget.set_text("")
            return
        index = row.get_index()
        if index < 0 or index >= len(self._visible):
            return
        event = self._visible[index]
        explanation = interpret(event)
        self.details_title.set_text(event.headline)
        self.details_meta.set_text(
            f"Audit serial {event.event_id} • UTC {event.timestamp_utc}"
            + (f" • PID {event.pid}" if event.pid else "")
        )
        self.facts_label.set_text(explanation.observed)
        self.context_label.set_text(
            f"Source: {event.source_context or '(missing)'}\n"
            f"Target: {event.target_context or '(missing)'}\n"
            f"Object class: {event.target_class or '(missing)'}\n"
            f"Target name/path: {event.target or '(not present in AVC)'}"
        )
        self.hypotheses_label.set_text(
            "\n\n".join("• " + item for item in explanation.possible_explanations)
        )
        self.checks_label.set_text(
            "\n".join("• " + item for item in explanation.next_checks)
        )
        self.raw_label.set_text(event.raw)

    def _export_clicked(self, _button: Gtk.Button) -> None:
        if self._export_dialog is not None:
            return
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
                    if chosen is None or chosen.get_path() is None:
                        self.notice_label.set_text(
                            "Only local file destinations are supported for v0.1."
                        )
                    else:
                        Path(chosen.get_path()).write_text(
                            serialize_report(self._snapshot), encoding="utf-8"
                        )
                        self.notice_label.set_text(
                            "Export complete (target paths redacted)."
                        )
            except OSError as exc:
                self.notice_label.set_text(f"Export failed: {exc}")
            finally:
                self._export_dialog = None
                chooser.destroy()

        dialog.connect("response", response)
        dialog.show()


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
