"""Files: SFTP browser with upload/download, mkdir, rename, delete, transfer."""

import os
import posixpath

from rich.text import Text
from textual.markup import escape as esc
from textual.binding import Binding
from textual.widgets import DataTable, Static

from ...backend.errors import BackendError
from ..dialogs import ConfirmDialog, PromptDialog, TransferDialog
from ..formatting import fmt_bytes, fmt_mode, fmt_mtime
from ..styles.theme import P
from .base import CANCELLED, BaseTab
from ...core.sanitize import clean_text, safe_filename


class FilesTab(BaseTab):
    TAB_ID = "files"
    TITLE = "5 Files"

    EXTRA_KEYS = [("enter", "open dir")]
    BINDINGS = [
        Binding("backspace", "up", "parent", key_display="bksp"),
        Binding("p", "goto", "go to path"),
        Binding("full_stop", "toggle_hidden", "hidden files", key_display="."),
        Binding("u", "upload", "upload"),
        Binding("g", "download", "download"),
        Binding("t", "transfer", "transfer"),
        Binding("n", "mkdir", "mkdir"),
        Binding("r", "rename", "rename"),
        Binding("d", "delete", "delete"),
        Binding("R", "reload_dir", "reload", key_display="R"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.path = "/"
        self.entries = []
        self.show_hidden = True

    def compose(self):
        yield Static("/", id="files-path", classes="subline")
        yield DataTable(id="files-table", cursor_type="row")

    def on_mount(self):
        self.table.add_columns("Name", "Type", "Size", "Modified", "Permissions")

    @property
    def table(self):
        return self.query_one("#files-table", DataTable)

    def focus_primary(self):
        self.table.focus()

    def on_server_changed(self):
        self.path = "/"
        self.entries = []
        self.table.clear()
        self.query_one("#files-path", Static).update(
            f"{esc(self.current)}:/" if self.current else "No server selected"
        )

    async def reload(self, select=None):
        if not self.require_connection():
            return

        server, path = self.current, self.path

        try:
            entries = await self.backend.files.list_dir(server, path)
        except Exception as exc:
            self.notify(f"Files: {exc}", severity="error")
            return

        if server != self.current or path != self.path:
            return

        self.entries = entries
        self._redraw(select)

    def _redraw(self, select=None):
        table = self.table
        table.clear()

        if self.path != "/":
            table.add_row(Text("..", style=P.dim), "dir", "", "", "", key="..")

        shown = 0
        for e in self.entries:
            if not self.show_hidden and e["name"].startswith("."):
                continue
            shown += 1
            table.add_row(
                Text(e.get("display", e["name"]) + ("/" if e["is_dir"] else ""), style=f"bold {P.accent}" if e["is_dir"] else ""),
                "dir" if e["is_dir"] else "file",
                "" if e["is_dir"] else fmt_bytes(e["size"]),
                fmt_mtime(e.get("modified")),
                fmt_mode(e["permissions"]),
                key=e["name"],
            )

        if select is not None:
            try:
                table.move_cursor(row=table.get_row_index(select))
            except Exception:
                pass

        hidden = "" if self.show_hidden else "   (hidden files off — press .)"
        self.query_one("#files-path", Static).update(
            f"[b]{esc(self.current)}[/b]:{esc(clean_text(self.path))}   {shown} item(s){hidden}"
        )

    def restyle(self):
        if self.entries:
            self._redraw()

    def _refresh(self, select=None):
        self.app.spawn(self.reload(select=select), group="reload-files", exclusive=True)

    async def _refresh_if_current(self, server, select=None):
        if server == self.current and self.backend.is_connected(server):
            await self.reload(select=select)

    def _selected(self):
        table = self.table
        if table.row_count == 0:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None
        if key == "..":
            return None
        return next((e for e in self.entries if e["name"] == key), None)

    # ------------------------------------------------------------------
    # navigation
    # ------------------------------------------------------------------
    def on_data_table_row_selected(self, ev):
        ev.stop()
        key = ev.row_key.value
        if key == "..":
            self.action_up()
            return
        for e in self.entries:
            if e["name"] == key and e["is_dir"]:
                self.path = posixpath.join(self.path, key)
                self._refresh()
                return

    def action_up(self):
        if self.path == "/":
            return
        child = posixpath.basename(self.path.rstrip("/"))
        self.path = posixpath.dirname(self.path.rstrip("/")) or "/"
        self._refresh(select=child)

    def action_goto(self):
        if not self.require_connection():
            return

        def done(path):
            if not path:
                return
            if not path.startswith("/"):
                path = posixpath.join(self.path, path)
            self.path = posixpath.normpath(path)
            self._refresh()

        self.app.push_screen(
            PromptDialog("Go to remote directory", initial=self.path, hint="absolute or relative to the current directory"),
            done,
        )

    def action_toggle_hidden(self):
        self.show_hidden = not self.show_hidden
        self._redraw()

    def action_reload_dir(self):
        if self.require_connection():
            self._refresh()

    # ------------------------------------------------------------------
    # shared "operation with overwrite confirmation" flow
    # ------------------------------------------------------------------
    async def _with_overwrite(self, label, exists_marker, confirm_title, confirm_msg, make_call):
        """
        make_call(overwrite) -> callback(passwords). Runs once without
        overwrite; if the backend reports that the destination exists,
        asks the user and retries with overwrite=True.
        Returns the result, CANCELLED, or raises.
        """
        try:
            return await self.run_with_sudo(label, make_call(False))
        except BackendError as exc:
            if exists_marker not in str(exc):
                raise

        if not await self.app.ask(ConfirmDialog(confirm_title, confirm_msg)):
            self.notify(f"{label}: cancelled", severity="warning")
            return CANCELLED

        return await self.run_with_sudo(label, make_call(True))

    # ------------------------------------------------------------------
    # upload / download
    # ------------------------------------------------------------------
    def action_upload(self):
        if not self.require_connection():
            return

        server, cwd = self.current, self.path

        def done(path):
            if not path:
                return
            local = os.path.abspath(os.path.expanduser(path))
            filename = os.path.basename(local)
            if not filename:
                self.notify("Invalid local file path", severity="warning")
                return
            self.app.spawn(self._upload(server, local, posixpath.join(cwd, filename)))

        self.app.push_screen(
            PromptDialog(
                "Upload: local file path",
                placeholder="~/file.txt",
                hint=f"uploads into {server}:{cwd}",
            ),
            done,
        )

    async def _upload(self, server, local, remote):
        try:
            with self.app.busy(f"uploading {os.path.basename(local)}"):
                result = await self._with_overwrite(
                    "upload",
                    "Destination already exists",
                    "Overwrite remote file",
                    f"'{remote}' already exists.\nOverwrite it?",
                    lambda ow: lambda pw: self.backend.files.upload(
                        server, local, remote, sudo_password=pw.get(server), overwrite=ow
                    ),
                )
            if result is not CANCELLED:
                self.notify(f"Uploaded to {remote}")
        except Exception as exc:
            self.notify(str(exc), severity="error")

        await self._refresh_if_current(server, select=posixpath.basename(remote))
        self.app.refresh_audit()

    def action_download(self):
        if not self.require_connection():
            return

        entry = self._selected()
        if not entry or entry["is_dir"]:
            self.notify("Select a file (not a directory) first", severity="warning")
            return

        server = self.current
        remote = posixpath.join(self.path, entry["name"])

        def done(path):
            if not path:
                return
            local = os.path.abspath(os.path.expanduser(path))
            if os.path.isdir(local):
                local = os.path.join(local, safe_filename(entry["name"]))
            self.app.spawn(self._download(server, remote, local))

        self.app.push_screen(
            PromptDialog(
                "Download: local destination",
                initial=os.path.join(os.path.expanduser("~"), safe_filename(entry["name"])),
                hint="a directory or a full file path",
            ),
            done,
        )

    async def _download(self, server, remote, local):
        try:
            with self.app.busy(f"downloading {posixpath.basename(remote)}"):
                result = await self._with_overwrite(
                    "download",
                    "Local destination already exists",
                    "Overwrite local file",
                    f"'{local}' already exists.\nOverwrite it?",
                    lambda ow: lambda pw: self.backend.files.download(
                        server, remote, local, sudo_password=pw.get(server), overwrite=ow
                    ),
                )
            if result is not CANCELLED:
                self.notify(f"Downloaded to {local}")
        except Exception as exc:
            self.notify(str(exc), severity="error")

        self.app.refresh_audit()

    # ------------------------------------------------------------------
    # mkdir / rename / delete
    # ------------------------------------------------------------------
    @staticmethod
    def _valid_name(name):
        return name and name not in (".", "..") and "/" not in name

    def action_mkdir(self):
        if not self.require_connection():
            return
        server, cwd = self.current, self.path

        def done(name):
            if not name:
                return
            if not self._valid_name(name):
                self.notify("Enter a directory name, not a path", severity="warning")
                return
            self.app.spawn(self._mkdir(server, posixpath.join(cwd, name)))

        self.app.push_screen(PromptDialog("New directory name", hint=f"in {server}:{cwd}"), done)

    async def _mkdir(self, server, remote):
        try:
            result = await self.run_with_sudo(
                "create_directory",
                lambda pw: self.backend.files.make_dir(server, remote, sudo_password=pw.get(server)),
            )
            if result is not CANCELLED:
                self.notify(f"Directory created: {remote}")
        except Exception as exc:
            self.notify(str(exc), severity="error")

        await self._refresh_if_current(server, select=posixpath.basename(remote))
        self.app.refresh_audit()

    def action_rename(self):
        if not self.require_connection():
            return
        entry = self._selected()
        if not entry:
            self.notify("Select a file or directory first", severity="warning")
            return

        server, cwd = self.current, self.path
        old_path = posixpath.join(cwd, entry["name"])

        def done(new_name):
            if not new_name or new_name == entry["name"]:
                return
            if not self._valid_name(new_name):
                self.notify("Enter a new name, not a path", severity="warning")
                return
            self.app.spawn(self._rename(server, old_path, posixpath.join(cwd, new_name)))

        self.app.push_screen(PromptDialog("Rename to", initial=entry.get("display", entry["name"])), done)

    async def _rename(self, server, old_path, new_path):
        try:
            result = await self.run_with_sudo(
                "rename",
                lambda pw: self.backend.files.rename(
                    server, old_path, new_path, sudo_password=pw.get(server)
                ),
            )
            if result is not CANCELLED:
                self.notify(f"Renamed: {posixpath.basename(old_path)} -> {posixpath.basename(new_path)}")
        except Exception as exc:
            self.notify(str(exc), severity="error")

        await self._refresh_if_current(server, select=posixpath.basename(new_path))
        self.app.refresh_audit()

    def action_delete(self):
        if not self.require_connection():
            return
        entry = self._selected()
        if not entry:
            self.notify("Select a file or directory first", severity="warning")
            return

        server = self.current
        remote = posixpath.join(self.path, entry["name"])
        is_dir = entry["is_dir"]

        message = (
            f"Delete EMPTY directory {remote}?\n(Fails if the directory is not empty.)"
            if is_dir
            else f"Delete file {remote}?"
        )

        def done(ok):
            if ok:
                self.app.spawn(self._delete(server, remote, is_dir))

        self.app.push_screen(
            ConfirmDialog("Delete directory" if is_dir else "Delete file", message), done
        )

    async def _delete(self, server, remote, is_dir):
        files = self.backend.files
        call = files.delete_dir if is_dir else files.delete_file

        try:
            result = await self.run_with_sudo(
                "delete_directory" if is_dir else "delete_file",
                lambda pw: call(server, remote, sudo_password=pw.get(server)),
            )
            if result is not CANCELLED:
                self.notify(f"Deleted {remote}")
        except Exception as exc:
            self.notify(str(exc), severity="error")

        await self._refresh_if_current(server)
        self.app.refresh_audit()

    # ------------------------------------------------------------------
    # server-to-server transfer
    # ------------------------------------------------------------------
    def action_transfer(self):
        if not self.require_connection():
            return

        entry = self._selected()
        if not entry or entry["is_dir"]:
            self.notify("Select a regular file to transfer", severity="warning")
            return

        source_server = self.current
        source_path = posixpath.join(self.path, entry["name"])
        candidates = [
            (n, self.backend.is_connected(n))
            for n in self.backend.servers.names()
            if n != source_server
        ]

        if not candidates:
            self.notify("Add a second server to transfer files between servers", severity="warning")
            return

        def done(values):
            if not values:
                return
            if not self.backend.is_connected(source_server):
                self.notify("Source server is no longer connected", severity="warning")
                return
            self.app.spawn(
                self._transfer(
                    source_server,
                    source_path,
                    values["destination_server"],
                    values["destination_path"],
                    values["mode"],
                )
            )

        self.app.push_screen(TransferDialog(source_server, source_path, candidates), done)

    async def _transfer(self, src, src_path, dst, dst_path, mode):
        # One progress record for this whole operation: every retry (after a
        # sudo prompt or an overwrite confirmation) resumes from it.
        progress = {}
        try:
            with self.app.busy(f"{mode} {posixpath.basename(src_path)} → {dst}"):
                result = await self._with_overwrite(
                    "server_transfer",
                    "Destination already exists",
                    "Overwrite destination",
                    f"{dst}:{dst_path}\nalready exists.\nOverwrite it?",
                    lambda ow: lambda pw: self.backend.files.transfer(
                        src, src_path, dst, dst_path, mode=mode, sudo_passwords=pw,
                        overwrite=ow, progress=progress,
                    ),
                )
            if result is not CANCELLED:
                self.notify(f"{mode.capitalize()} completed and SHA-256 verified")
                if mode == "move":
                    await self._refresh_if_current(src)
        except Exception as exc:
            self.notify(f"Transfer failed: {exc}", severity="error", timeout=10)

        self.app.refresh_audit()
