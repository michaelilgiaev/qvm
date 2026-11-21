"""configuration_tui.py - the `qvm --configure` terminal UI for hypervisor.cfg.

`qvm --configure` with no further option opens this editor on the CURRENT directory's
hypervisor.cfg (the file `qvm install` writes, and the file a running VM reloads live).
It is deliberately not the global-defaults editor: `--status`, `--set`, and `--reset`
still manage ~/.config/azzio-hypervisor/defaults.cfg. A value left untouched here keeps
inheriting those defaults; env overrides are runtime-only and are never shown or saved.

The screen is curses. Everything it decides -- load, edit, validate, and how a save
rewrites the file -- lives on Form and Session so the tests exercise it without a
terminal. Saving is surgical: the lines you changed are updated in place (comments,
`vm_name`, and every untouched line stay), and a directory that had no file yet gets
a header plus only the settings you actually changed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configuration  # noqa: E402
import configuration_schema  # noqa: E402
from checks import HypervisorError  # noqa: E402

try:
    import curses
except ImportError:  # a Python built without _curses; run() reports it
    curses = None  # type: ignore[assignment]


# One line of guidance per schema key, shown under the field list. Wording follows
# the usage text in command_line_interface.py so the UI and the help agree.
FIELD_HELP = {
    "Share_Host_GPU": "Guest uses the host GPU (shared, not passthrough). False = software GPU.",
    "Network": '"user" (NAT), "none", or a host interface. Space cycles the choices.',
    "Proxy": 'False, True (the proxies file, one URL per line), or a socks4://, socks5://, or http:// URL.',
    "Proxy_Kill_Switch": "Cut the guest's internet when the proxy drops. Off switches as soon as this proxy stops answering.",
    "Shared": "False, True (this directory), or an absolute host path shared via virtiofs.",
    "Clipboard": "Share the clipboard between the host and the guest (SPICE vdagent).",
    "Secure_Shell": "Forward the guest SSH port to the host.",
    "Ports": 'Guest:host forwards, for example 22:49156, 1500:49157. False means none.',
    "Ssh_Forward_Port": "Base host port for guest port 22 (49350, plus 1 per running VM).",
    "USB": "False, or absolute device paths (lsusb, lsblk -o NAME,TRAN,MOUNTPOINT).",
    "Fullscreen": "Borderless exclusive fullscreen for the viewer window.",
    "Ask_Before_Quitting_Hypervisor": "Ask before closing the viewer window.",
    "RAM": "Guest RAM in MiB, or a percent of host RAM such as 15%.",
    "CPUs": "vCPU count, or a percent of the host CPUs such as 15%.",
    "Disk_Size_GB": "Disk size in GiB, or a percent of the host disk such as 15%.",
    "Audio": "True enables PipeWire audio. False is silent.",
}

# Bool toggles. Shared and Network look similar but are not booleans: Shared may be
# a path, Network is a name, and both have their own space-bar cycle below.
_BOOL_KEYS = {
    "Share_Host_GPU",
    "Clipboard",
    "Secure_Shell",
    "Fullscreen",
    "Ask_Before_Quitting_Hypervisor",
    "Audio",
    "Proxy_Kill_Switch",
}

_NAV_HINT = " arrows/jk move   enter edit   space toggle   s save   q quit   ? help"
_EDIT_HINT = " editing    enter confirm    esc cancel    Ctrl-U clear"
_REPLACE_HINT = " type to replace    enter confirm    esc cancel    backspace clear"
_QUIT_HINT = " Save changes to hypervisor.cfg?   y save    n discard    esc cancel"

_HELP_LINES = (
    "qvm --configure edits hypervisor.cfg in the current directory.",
    "A running VM applies a valid save live, and reverts an invalid file.",
    "",
    "Up/Down or j/k       move between settings (arrow keys too)",
    "Enter or e           edit; typing replaces the current value",
    "Space                toggle True/False; cycle Network and Shared",
    "Tab                  cycle Network, otherwise move down",
    "Left/Right           move inside the value being edited",
    "d                    reset the selected setting to its default",
    "s                    save hypervisor.cfg",
    "q                    quit, and ask when there are unsaved edits",
    "?                    this help",
    "Esc                  cancel an edit, or close this help",
    "",
    "Save rewrites only the settings you changed. Comments, vm_name,",
    "and every untouched line stay put. A new file gets a short header",
    "and just those settings; everything else keeps inheriting defaults.",
    "Env overrides (RAM=...) are not shown here and are not saved.",
    "",
    "Ctrl-C aborts the editor and does not save.",
    "Up/Down scrolls this help. Any other key closes it.",
)


def display_value(raw: str) -> str:
    """The value as a person reads it. File form quotes strings; the screen does not."""
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    return raw


def host_interfaces() -> list[str]:
    """Host interface names Network will accept, skipping lo. Empty when `ip` is absent."""
    try:
        proc = subprocess.run(
            ["ip", "-br", "addr"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    names: list[str] = []
    for line in proc.stdout.split("\n"):
        parts = line.split()
        if not parts:
            continue
        name = parts[0].split("@", 1)[0]
        if not name or name == "lo" or name in names:
            continue
        ok, _val, _err = configuration_schema.coerce_one("Network", name)
        if ok:
            names.append(name)
    return names


def _setting_key(line: str) -> "str | None":
    """The canonical schema key a cfg line sets, or None for comments and unknown keys.

    Legacy names (`ssh`, `sshd`, `disk_size`, ...) count as the key they migrate to,
    so editing Secure_Shell rewrites an old `ssh =` line instead of appending a second
    one. `vm_name` and comments return None and are copied through unchanged.
    """
    body = line.split("#", 1)[0]
    if "=" not in body:
        return None
    raw_key = body.split("=", 1)[0].strip()
    if not raw_key:
        return None
    low = raw_key.lower()
    if low == "disk_size":
        return "Disk_Size_GB"
    legacy = configuration._LEGACY_KEY_ALIASES.get(low)
    if legacy:
        return legacy
    return configuration_schema.canonical_key(raw_key)


def _comment_suffix(line: str) -> str:
    """The `  # ...` tail of a setting line, or '' when the line has no comment."""
    _body, hash_mark, comment = line.partition("#")
    if not hash_mark:
        return ""
    return "  #" + comment


def _is_blank(text: str) -> bool:
    return all(not line.strip() for line in text.split("\n"))


def _insert_before_trailing_blanks(lines: list[str], extra: list[str]) -> list[str]:
    end = len(lines)
    while end > 0 and lines[end - 1] == "":
        end -= 1
    return lines[:end] + extra + lines[end:]


def _fresh_text(pairs: list[tuple[str, str]]) -> str:
    """A new hypervisor.cfg: the standard header, then only the settings we changed."""
    lines = [configuration._CFG_HEADER.rstrip("\n"), ""]
    lines.extend(f"{key} = {value}" for key, value in pairs)
    return "\n".join(lines) + "\n"


def _patch_text(original: str, updates: dict[str, str]) -> str:
    """Rewrite `updates` into `original`, leaving every other line byte-for-byte.

    The first line that sets a key (any casing, or a legacy alias) is replaced with
    the canonical `Key = value`, keeping its trailing comment. A later duplicate line
    for that same key is dropped. Keys that were not in the file are appended.
    """
    lines = original.split("\n")
    written: set[str] = set()
    out: list[str] = []
    for line in lines:
        canon = _setting_key(line)
        if canon is None or canon not in updates:
            out.append(line)
            continue
        if canon in written:
            continue
        out.append(f"{canon} = {updates[canon]}{_comment_suffix(line)}")
        written.add(canon)
    missing = [
        f"{key} = {updates[key]}"
        for key in configuration_schema.KEYS
        if key in updates and key not in written
    ]
    if missing:
        out = _insert_before_trailing_blanks(out, missing)
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text


class Form:
    """The editable hypervisor.cfg for one directory. No terminal and no global curses state.

    `values` and `defaults` hold the FILE form of each setting (`True`, `"user"`, `15%`),
    which is what a save writes. `original` is that map as loaded, so dirty-checking is a
    straight compare and an invalid line (`CPUs = lots`) stays on screen until it is fixed.
    """

    def __init__(self, directory: str):
        self.directory = os.path.abspath(directory)
        self.values: dict[str, str] = {}
        self.original: dict[str, str] = {}
        self.defaults: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self.explicit: set[str] = set()
        self.original_text: "str | None" = None
        self.existed = False

    @property
    def path(self) -> str:
        return os.path.join(self.directory, configuration._HYPERVISOR_CFG_NAME)

    @property
    def dirty_keys(self) -> list[str]:
        return [
            key for key in configuration_schema.KEYS
            if self.values.get(key) != self.original.get(key)
        ]

    @property
    def dirty(self) -> bool:
        return bool(self.dirty_keys)

    def tag(self, key: str) -> str:
        """Where the selected value came from, for the status line."""
        if key in self.errors:
            return "invalid"
        if self.values.get(key) != self.original.get(key):
            return "unsaved"
        if key in self.explicit:
            return "in file"
        return "default"

    @classmethod
    def load(cls, directory: str) -> "Form":
        """Load `directory`/hypervisor.cfg over the effective defaults.

        A missing file is not an error: every key shows its default (built-in, then the
        user's global defaults.cfg) and nothing is written until a save. A value the
        schema rejects is kept as text and recorded in `errors` so the UI can show it
        and refuse to save until it is fixed. Env vars are ignored on purpose.
        """
        form = cls(directory)
        defaults = configuration.effective_defaults()
        form.defaults = {
            key: configuration._render_value(key, defaults[key])
            for key in configuration_schema.KEYS
        }
        form.values = dict(form.defaults)
        if os.path.isfile(form.path):
            form.existed = True
            try:
                with open(form.path, encoding="utf-8", errors="replace") as fh:
                    form.original_text = fh.read()
            except OSError as exc:
                raise HypervisorError(
                    f"cannot read {form.path}: {exc.strerror or exc}"
                ) from exc
            migrated = configuration._migrate_legacy_keys(
                configuration.parse_conf_text(form.original_text)
            )
            for key, raw in migrated.items():
                canon = configuration_schema.canonical_key(key)
                if canon is None:
                    continue
                ok, val, err = configuration_schema.coerce_one(canon, raw)
                if ok and val is not None:
                    form.values[canon] = configuration._render_value(canon, val)
                else:
                    form.values[canon] = str(raw)
                    form.errors[canon] = err
            for line in form.original_text.split("\n"):
                canon = _setting_key(line)
                if canon:
                    form.explicit.add(canon)
        form.original = dict(form.values)
        return form

    def set_value(self, key: str, raw: str) -> tuple[bool, str]:
        """Validate `raw` and, on success, store the canonical file form. A rejection
        leaves the previous value in place (the editor keeps the typed text itself)."""
        canon = configuration_schema.canonical_key(key)
        if canon is None:
            return False, f"unknown key: {key}"
        ok, val, err = configuration_schema.coerce_one(canon, raw)
        if not ok or val is None:
            return False, err or "invalid value"
        self.values[canon] = configuration._render_value(canon, val)
        self.errors.pop(canon, None)
        return True, ""

    def reset_to_default(self, key: str) -> None:
        self.values[key] = self.defaults[key]
        self.errors.pop(key, None)

    def invalid_message(self) -> str:
        """The first setting that still does not validate, or '' when the file is saveable.

        Re-checks every key (not only the errors found at load) and refreshes `errors`
        so a value fixed through set_value is not reported twice."""
        for key in configuration_schema.KEYS:
            ok, _val, err = configuration_schema.coerce_one(key, self.values[key])
            if not ok:
                self.errors[key] = err
                return f"{key}: {err} (got '{self.values[key]}')"
            self.errors.pop(key, None)
        return ""

    def render_text(self) -> str:
        """The file body a save would write. Only dirty keys change."""
        updates = {key: self.values[key] for key in self.dirty_keys}
        if self.original_text is None or _is_blank(self.original_text):
            pairs = [(key, self.values[key]) for key in configuration_schema.KEYS if key in updates]
            return _fresh_text(pairs)
        return _patch_text(self.original_text, updates)

    def save(self) -> str:
        """Atomically write render_text() and treat the result as the new baseline.

        Raises ValueError when a value is invalid (the file is left untouched) and
        OSError when the directory cannot be written. A clean form writes nothing.
        """
        problem = self.invalid_message()
        if problem:
            raise ValueError(problem)
        if not self.dirty:
            return self.path
        changed = list(self.dirty_keys)
        text = self.render_text()
        _atomic_write(self.path, text)
        self.explicit.update(changed)
        self.original = dict(self.values)
        self.original_text = text
        self.existed = True
        return self.path


def _atomic_write(path: str, text: str) -> None:
    """Write `text` to `path` via a temp file in the same directory, then replace.

    mkstemp creates the temp mode 0600; restore the previous mode (or 0644 for a new
    file) before the replace so a save does not make hypervisor.cfg owner-only.
    """
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".hypervisor.cfg.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.exists(path):
            mode = os.stat(path).st_mode & 0o777
        else:
            mode = 0o644
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def commit_save(form: Form) -> tuple[bool, str]:
    """Save when there is something valid to save. (ok, message) for the status line."""
    problem = form.invalid_message()
    if problem:
        return False, f"Cannot save: {problem}"
    if not form.dirty:
        return True, "No changes to save."
    try:
        path = form.save()
    except OSError as exc:
        return False, f"Could not save {form.path}: {exc.strerror or exc}"
    return True, f"Saved {path}"


class Session:
    """Cursor, mode, and the edit buffer. `on_key` is pure: it mutates this session
    and the form, and returns 'save', 'save_quit', or 'quit' when the caller (the
    curses loop, or a test) has to do I/O or leave."""

    def __init__(self, form: Form, interfaces: "list[str] | None" = None):
        self.form = form
        self.interfaces = list(interfaces or [])
        self.index = 0
        self.mode = "nav"  # nav | edit | quit_ask | help
        self.buffer = ""
        self.buf_pos = 0
        self.status = ""
        self.status_bad = False
        self.help_scroll = 0
        self.scroll = 0
        self.page = 10
        # Enter selects the whole value, so the next key replaces it instead of
        # appending (typing 8192 onto "15%" used to produce the invalid "15%8192").
        self.replace = False

    @property
    def key(self) -> str:
        return configuration_schema.KEYS[self.index]

    def on_key(self, key: int) -> "str | None":
        if key < 0 or (curses is not None and key == curses.KEY_RESIZE):
            return None
        if self.mode == "help":
            return self._on_help(key)
        if self.mode == "quit_ask":
            return self._on_quit_ask(key)
        if self.mode == "edit":
            return self._on_edit(key)
        return self._on_nav(key)

    def _move(self, delta: int) -> None:
        last = len(configuration_schema.KEYS) - 1
        self.index = max(0, min(last, self.index + delta))

    def _begin_edit(self, seed: "str | None" = None) -> None:
        if seed is None:
            self.buffer = display_value(self.form.values[self.key])
            self.buf_pos = len(self.buffer)
            self.replace = True
        else:
            self.buffer = seed
            self.buf_pos = len(seed)
            self.replace = False
        self.mode = "edit"
        self.status = ""
        self.status_bad = False

    def _toggle_bool(self, key: str) -> None:
        ok, val, _err = configuration_schema.coerce_one(key, self.form.values[key])
        self.form.set_value(key, "False" if ok and val is True else "True")

    def _cycle_shared(self) -> None:
        ok, val, _err = configuration_schema.coerce_one("Shared", self.form.values["Shared"])
        # False -> share this directory. True or a path -> off. A path is typed, not cycled.
        self.form.set_value("Shared", "True" if ok and val is False else "False")

    def _cycle_network(self, step: int) -> None:
        ok, val, _err = configuration_schema.coerce_one("Network", self.form.values["Network"])
        current = val if ok else ""
        options = ["user", "none"]
        for name in self.interfaces:
            if name in options:
                continue
            accept, _v, _e = configuration_schema.coerce_one("Network", name)
            if accept:
                options.append(name)
        if current in options:
            nxt = options[(options.index(current) + step) % len(options)]
        else:
            nxt = options[0] if step > 0 else options[-1]
        self.form.set_value("Network", nxt)

    def _on_help(self, key: int) -> None:
        if _is_up(key):
            self.help_scroll = max(0, self.help_scroll - 1)
            return None
        if _is_down(key):
            self.help_scroll += 1
            return None
        self.mode = "nav"
        self.help_scroll = 0
        return None

    def _on_quit_ask(self, key: int) -> "str | None":
        if key in (ord("y"), ord("Y")):
            return "save_quit"
        if key in (ord("n"), ord("N")):
            return "quit"
        if key == 27 or key in (ord("c"), ord("C")):
            self.mode = "nav"
            self.status = ""
            self.status_bad = False
        return None

    def _on_edit(self, key: int) -> None:
        if key == 27:
            self.mode = "nav"
            self.replace = False
            self.status = ""
            self.status_bad = False
            return None
        if _is_enter(key):
            ok, err = self.form.set_value(self.key, self.buffer)
            if ok:
                self.mode = "nav"
                self.replace = False
                self.status = ""
                self.status_bad = False
            else:
                self.status = f"{self.key}: {err}"
                self.status_bad = True
            return None
        # The value is selected: the first edit replaces it, like a form field.
        if self.replace and (_is_backspace(key) or (curses is not None and key == curses.KEY_DC)):
            self.buffer = ""
            self.buf_pos = 0
            self.replace = False
            return None
        if self.replace and curses is not None and key == curses.KEY_LEFT:
            self.buf_pos = 0
            self.replace = False
            return None
        if self.replace and curses is not None and key == curses.KEY_RIGHT:
            self.buf_pos = len(self.buffer)
            self.replace = False
            return None
        if self.replace and _is_printable(key):
            self.buffer = chr(key)
            self.buf_pos = 1
            self.replace = False
            return None
        if _is_backspace(key):
            if self.buf_pos > 0:
                self.buffer = self.buffer[: self.buf_pos - 1] + self.buffer[self.buf_pos :]
                self.buf_pos -= 1
            return None
        if curses is not None and key == curses.KEY_DC:
            if self.buf_pos < len(self.buffer):
                self.buffer = self.buffer[: self.buf_pos] + self.buffer[self.buf_pos + 1 :]
            return None
        if curses is not None and key == curses.KEY_LEFT:
            self.replace = False
            self.buf_pos = max(0, self.buf_pos - 1)
            return None
        if curses is not None and key == curses.KEY_RIGHT:
            self.replace = False
            self.buf_pos = min(len(self.buffer), self.buf_pos + 1)
            return None
        if key == 1 or (curses is not None and key == curses.KEY_HOME):  # Ctrl-A
            self.buf_pos = 0
            self.replace = False
            return None
        if key == 5 or (curses is not None and key == curses.KEY_END):  # Ctrl-E
            self.buf_pos = len(self.buffer)
            self.replace = False
            return None
        if key == 21:  # Ctrl-U
            self.buffer = ""
            self.buf_pos = 0
            self.replace = False
            return None
        if key == 23:  # Ctrl-W, delete the word before the cursor
            self.replace = False
            pos = self.buf_pos
            while pos > 0 and self.buffer[pos - 1] == " ":
                pos -= 1
            while pos > 0 and self.buffer[pos - 1] != " ":
                pos -= 1
            self.buffer = self.buffer[:pos] + self.buffer[self.buf_pos :]
            self.buf_pos = pos
            return None
        if _is_printable(key):
            ch = chr(key)
            self.buffer = self.buffer[: self.buf_pos] + ch + self.buffer[self.buf_pos :]
            self.buf_pos += 1
        return None

    def _on_nav(self, key: int) -> "str | None":
        # Drop a transient status ("Saved ...") once the user does something else.
        self.status = ""
        self.status_bad = False
        if _is_up(key):
            self._move(-1)
            return None
        if _is_down(key):
            self._move(1)
            return None
        if _is_page_up(key):
            self._move(-self.page)
            return None
        if _is_page_down(key):
            self._move(self.page)
            return None
        if _is_home(key):
            self.index = 0
            return None
        if _is_end(key):
            self.index = len(configuration_schema.KEYS) - 1
            return None
        if _is_tab(key):
            if self.key == "Network":
                self._cycle_network(1)
            else:
                self._move(1)
            return None
        if _is_backtab(key):
            if self.key == "Network":
                self._cycle_network(-1)
            else:
                self._move(-1)
            return None
        if key == ord(" "):
            if self.key in _BOOL_KEYS:
                self._toggle_bool(self.key)
            elif self.key == "Shared":
                self._cycle_shared()
            elif self.key == "Network":
                self._cycle_network(1)
            else:
                self.status = f"Press enter to edit {self.key}."
            return None
        if _is_enter(key) or key in (ord("e"), ord("E")):
            self._begin_edit()
            return None
        if key in (ord("d"), ord("D")):
            self.form.reset_to_default(self.key)
            shown = display_value(self.form.values[self.key])
            self.status = f"{self.key} reset to default ({shown})."
            return None
        if key == ord("?"):
            self.mode = "help"
            self.help_scroll = 0
            return None
        if key in (ord("q"), ord("Q")):
            if self.form.dirty:
                self.mode = "quit_ask"
                return None
            return "quit"
        if key in (ord("s"), ord("S")):
            return "save"
        # A digit (or '%' or '/') replaces a free-form value immediately, so RAM,
        # a port, or a path can be typed without an extra key. Command letters
        # (s/q/d/...) keep their meaning and never start an edit.
        if self.key not in _BOOL_KEYS and _is_printable(key) and _typeahead_ok(self.key, key):
            self._begin_edit(chr(key))
        return None


def _is_printable(key: int) -> bool:
    return 32 <= key <= 126


def _typeahead_ok(field: str, key: int) -> bool:
    """Digits, '%', ':', ',', and '/' start an edit. Other letters go through commands
    or are ignored, so a stray key cannot wipe a value."""
    ch = chr(key)
    if ch.isdigit() or ch in "%/,.:":
        return True
    if field in ("Network", "Shared", "USB", "Ports", "Proxy") and ch.isalpha():
        return True
    return False


def _is_enter(key: int) -> bool:
    if key in (10, 13):
        return True
    return curses is not None and key == curses.KEY_ENTER


def _is_backspace(key: int) -> bool:
    if key in (127, 8):
        return True
    return curses is not None and key == curses.KEY_BACKSPACE


def _is_up(key: int) -> bool:
    if key == ord("k"):
        return True
    return curses is not None and key == curses.KEY_UP


def _is_down(key: int) -> bool:
    if key == ord("j"):
        return True
    return curses is not None and key == curses.KEY_DOWN


def _is_page_up(key: int) -> bool:
    return curses is not None and key == curses.KEY_PPAGE


def _is_page_down(key: int) -> bool:
    return curses is not None and key == curses.KEY_NPAGE


def _is_home(key: int) -> bool:
    return curses is not None and key == curses.KEY_HOME


def _is_end(key: int) -> bool:
    return curses is not None and key == curses.KEY_END


def _is_tab(key: int) -> bool:
    return key == 9


def _is_backtab(key: int) -> bool:
    return curses is not None and key == getattr(curses, "KEY_BTAB", -1)


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _edit_window(text: str, pos: int, width: int) -> tuple[str, int]:
    """The slice of an edit buffer that fits `width`, and the cursor's column inside it."""
    if width <= 0:
        return "", 0
    pos = max(0, min(pos, len(text)))
    if len(text) < width:
        return text, pos
    start = pos - width + 1 if pos >= width else 0
    return text[start : start + width], pos - start


def _put(win, y: int, x: int, text: str, attr: int = 0) -> None:
    """addnstr that never raises when the cursor would land on the bottom-right cell."""
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width or not text:
        return
    if x < 0:
        text = text[-x:]
        x = 0
        if not text:
            return
    limit = width - x
    if y == height - 1:
        limit -= 1
    if limit <= 0:
        return
    try:
        win.addnstr(y, x, text, limit, attr)
    except curses.error:
        pass


def _bar(win, y: int, text: str, attr: int) -> None:
    _height, width = win.getmaxyx()
    _put(win, y, 0, text.ljust(width), attr)


def _color(enabled: bool, pair: int, extra: int = 0) -> int:
    if enabled:
        return curses.color_pair(pair) | extra
    return extra


def _init_colors() -> bool:
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE)
        # The value selected by Enter, so typing reads as replacing it, not appending.
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    except curses.error:
        return False
    return True


def _title_attr(colors: bool) -> int:
    if colors:
        return _color(True, 1, curses.A_BOLD)
    return curses.A_REVERSE | curses.A_BOLD


def _hint_attr(colors: bool) -> int:
    if colors:
        return _color(True, 5, curses.A_BOLD)
    return curses.A_REVERSE


def _draw(stdscr, session: Session, colors: bool) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height < 8 or width < 40:
        _put(stdscr, 0, 0, "Terminal too small. Resize it, or press q to quit.", curses.A_BOLD)
        stdscr.refresh()
        return
    if session.mode == "help":
        _draw_help(stdscr, session, colors, height, width)
        return
    _draw_form(stdscr, session, colors, height, width)


def _draw_help(stdscr, session: Session, colors: bool, height: int, width: int) -> None:
    _bar(stdscr, 0, " qvm --configure help", _title_attr(colors))
    top = 2
    visible = max(1, height - 3)
    max_scroll = max(0, len(_HELP_LINES) - visible)
    session.help_scroll = max(0, min(session.help_scroll, max_scroll))
    for row in range(visible):
        index = session.help_scroll + row
        if index >= len(_HELP_LINES):
            break
        _put(stdscr, top + row, 1, _HELP_LINES[index])
    _bar(stdscr, height - 1, " up/down scroll    any other key closes", _hint_attr(colors))
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.refresh()


def _draw_form(stdscr, session: Session, colors: bool, height: int, width: int) -> None:
    form = session.form
    count = len(configuration_schema.KEYS)
    left = " qvm  configure hypervisor.cfg"
    right = f"{session.index + 1}/{count}"
    if form.dirty:
        right = "unsaved  " + right
    gap = max(1, width - len(left) - len(right))
    _bar(stdscr, 0, left + (" " * gap) + right, _title_attr(colors))

    path = form.path
    if not form.existed:
        path += "   (new file, save creates it)"
    _put(stdscr, 1, 0, " " + path, curses.A_DIM)

    body_top = 3
    body_bottom = height - 4
    body_h = max(1, body_bottom - body_top + 1)
    session.page = body_h
    if session.index < session.scroll:
        session.scroll = session.index
    if session.index >= session.scroll + body_h:
        session.scroll = session.index - body_h + 1

    label_w = 2 + max(len(key) for key in configuration_schema.KEYS) + 2
    cursor_y = 0
    cursor_x = 0
    editing = False
    for row in range(body_h):
        key_i = session.scroll + row
        if key_i >= count:
            break
        key = configuration_schema.KEYS[key_i]
        y = body_top + row
        selected = key_i == session.index
        if selected:
            _put(stdscr, y, 0, " " * max(1, width - 1), curses.A_REVERSE)
        if selected:
            marker = ">"
        elif key in form.errors:
            marker = "!"
        else:
            marker = " "
        shown = display_value(form.values[key])
        if session.mode == "edit" and selected:
            shown = session.buffer
        attr = curses.A_REVERSE if selected else 0
        if selected:
            attr |= curses.A_BOLD
        elif key in form.errors and colors:
            attr |= curses.color_pair(3)
        _put(stdscr, y, 0, f"{marker} {key}".ljust(label_w), attr)
        val_attr = attr
        if session.mode == "edit" and selected and session.replace:
            # Paint the whole value, not a cursor at the end of it. The row behind
            # it stays reversed; this background is what says "the next key replaces".
            if colors:
                val_attr = curses.color_pair(6) | curses.A_BOLD
            else:
                val_attr = curses.A_UNDERLINE | curses.A_BOLD
        elif not selected and shown == "True" and colors:
            val_attr |= curses.color_pair(2)
        elif not selected and shown == "False":
            val_attr |= curses.A_DIM
        val_w = max(1, width - label_w - 2)
        if session.mode == "edit" and selected:
            visible, col = _edit_window(shown, session.buf_pos, val_w)
            _put(stdscr, y, label_w, visible, val_attr)
            cursor_y, cursor_x = y, label_w + col
            editing = True
        else:
            _put(stdscr, y, label_w, _clip(shown, val_w), val_attr)
        if form.values[key] != form.original[key]:
            if colors and not selected:
                star = _color(True, 4, curses.A_BOLD)
            else:
                star = attr
            _put(stdscr, y, width - 2, "*", star)

    if session.mode == "edit":
        hint = _REPLACE_HINT if session.replace else _EDIT_HINT
    elif session.mode == "quit_ask":
        hint = _QUIT_HINT
    else:
        hint = _NAV_HINT
    _bar(stdscr, height - 2, hint, _hint_attr(colors))

    if session.status:
        text = " " + session.status
        if session.status_bad:
            attr = _color(colors, 3, curses.A_BOLD)
        elif session.status.startswith("Saved"):
            attr = _color(colors, 2, curses.A_BOLD)
        else:
            attr = 0
    elif session.key in form.errors:
        text = f" [invalid]  {session.key}: {form.errors[session.key]}"
        attr = _color(colors, 3, curses.A_BOLD)
    else:
        text = f" [{form.tag(session.key)}]  {FIELD_HELP[session.key]}"
        attr = curses.A_DIM
    _put(stdscr, height - 1, 0, text, attr)

    try:
        if editing:
            curses.curs_set(1)
            stdscr.move(cursor_y, min(cursor_x, width - 2))
        else:
            curses.curs_set(0)
    except curses.error:
        pass
    stdscr.refresh()


def _sequence_complete(parts: list[int]) -> bool:
    """True when `parts` (the bytes after Esc) is a finished SS3 or CSI sequence.

    A CSI final is 0x40-0x7E, but the introducer `[` itself sits in that range, so
    the first byte never counts. Cap the length so a stray Esc cannot stall the UI.
    """
    if not parts:
        return False
    if parts[0] == ord("O"):
        return len(parts) >= 2
    if parts[0] == ord("["):
        if len(parts) >= 16:
            return True
        return len(parts) >= 2 and 0x40 <= parts[-1] <= 0x7E
    return True


def _decode_sequence(parts: list[int]) -> int:
    """Map an SS3 or CSI sequence to a curses key, or -1 when it is not one we use.

    Modified keys (`\\E[1;5B`, ctrl-down) use the letter or the number before `;`.
    Anything else (F-keys, mouse) is ignored so it cannot land in a value.
    """
    if curses is None or not parts:
        return -1
    if parts[0] == ord("O") and len(parts) >= 2:
        return {
            ord("A"): curses.KEY_UP,
            ord("B"): curses.KEY_DOWN,
            ord("C"): curses.KEY_RIGHT,
            ord("D"): curses.KEY_LEFT,
            ord("H"): curses.KEY_HOME,
            ord("F"): curses.KEY_END,
        }.get(parts[1], -1)
    if parts[0] != ord("[") or len(parts) < 2:
        return -1
    final = parts[-1]
    number = ""
    for code in parts[1:-1]:
        if code == ord(";"):
            break
        if ord("0") <= code <= ord("9"):
            number += chr(code)
        else:
            number = ""
            break
    if final == ord("~"):
        return {
            "1": curses.KEY_HOME,
            "2": curses.KEY_IC,
            "3": curses.KEY_DC,
            "4": curses.KEY_END,
            "5": curses.KEY_PPAGE,
            "6": curses.KEY_NPAGE,
        }.get(number, -1)
    return {
        ord("A"): curses.KEY_UP,
        ord("B"): curses.KEY_DOWN,
        ord("C"): curses.KEY_RIGHT,
        ord("D"): curses.KEY_LEFT,
        ord("H"): curses.KEY_HOME,
        ord("F"): curses.KEY_END,
        ord("Z"): curses.KEY_BTAB,
    }.get(final, -1)


def read_key(getch, set_timeout, pending: "list[int] | None" = None) -> int:
    """One keypress. Arrow keys that curses did not translate still come back as arrows.

    xterm-256color names SS3 arrows (`\\EOA`) and only a few CSI keys. Terminals that
    ignore keypad mode send CSI (`\\E[A`). curses then returns Esc and leaves `[A` in
    the queue, and the `A` starts an edit on Network, Shared, Ports, or USB. A bare
    Esc stays Esc. The byte after it, when it is not the start of a sequence, is kept
    in `pending` for the next call -- pass the same list every time.
    """
    if pending is None:
        pending = []
    if pending:
        return pending.pop(0)
    key = getch()
    if key != 27:
        return key
    set_timeout(40)
    try:
        nxt = getch()
        if nxt < 0:
            return 27
        if nxt not in (ord("["), ord("O")):
            pending.append(nxt)
            return 27
        parts = [nxt]
        while not _sequence_complete(parts):
            more = getch()
            if more < 0:
                break
            parts.append(more)
    finally:
        set_timeout(-1)
    if not _sequence_complete(parts):
        return -1
    return _decode_sequence(parts)


def _loop(stdscr, session: Session) -> None:
    colors = _init_colors()
    stdscr.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    # Same list across reads so Esc followed by an ordinary key is not swallowed.
    pending: list[int] = []
    while True:
        _draw(stdscr, session, colors)
        key = read_key(stdscr.getch, stdscr.timeout, pending)
        action = session.on_key(key)
        if action in ("save", "save_quit"):
            ok, message = commit_save(session.form)
            session.status = message
            session.status_bad = not ok
            session.mode = "nav"
            if action == "save_quit" and ok:
                _draw(stdscr, session, colors)
                return
        elif action == "quit":
            return


def run(directory: "str | None" = None) -> int:
    """Open the editor on `directory` (default: the current directory). Returns an exit code.

    0 leaves the terminal normally (saved or not). 1 means there is no terminal, the
    file cannot be read, or curses cannot start. 130 is Ctrl-C, which saves nothing.
    """
    directory = os.path.abspath(directory or os.getcwd())
    if curses is None:
        print("qvm --configure: this Python has no curses support.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("qvm --configure: a terminal is required to edit hypervisor.cfg.", file=sys.stderr)
        print("Open an interactive terminal in the VM directory and run qvm --configure.",
              file=sys.stderr)
        return 1
    try:
        form = Form.load(directory)
    except HypervisorError as exc:
        print(f"qvm --configure: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"qvm --configure: {exc.strerror or exc}", file=sys.stderr)
        return 1
    # A stock ESCDELAY of 1000ms makes the Esc key feel stuck. Set it before initscr.
    os.environ.setdefault("ESCDELAY", "25")
    session = Session(form, host_interfaces())
    try:
        curses.wrapper(lambda stdscr: _loop(stdscr, session))
    except KeyboardInterrupt:
        return 130
    except curses.error as exc:
        print(f"qvm --configure: could not open the terminal UI ({exc}).", file=sys.stderr)
        return 1
    return 0
