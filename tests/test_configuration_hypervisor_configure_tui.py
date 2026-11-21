"""qvm --configure -- the terminal UI for this directory's hypervisor.cfg.

Bare `qvm --configure` edits ./hypervisor.cfg (the per-VM file). The global
defaults surface (`--set` / `--status` / `--reset`) is unchanged and covered in
test_configuration_hypervisor_defaults.py.

These tests drive Form and Session directly, so the decisions (what is loaded,
what an edit accepts, what a save rewrites) do not need a terminal. The tests at
the bottom run the real curses screen on a pty, including `qvm --configure`.
"""

from __future__ import annotations

import os
import select
import struct
import subprocess
import sys
import termios
import time

import pytest

import command_line_interface as cli
import configuration
import configuration_defaults as defaults
import configuration_schema
import configuration_tui as tui
from configuration import HypervisorCfg

try:
    import curses
    import fcntl
except ImportError:  # pragma: no cover - this tree runs on a curses build
    curses = None
    fcntl = None


_LIBRARIES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "libraries")

# Env overrides are runtime-only. A leaked RAM= in the test process must not
# show up as a cfg value, and must not be written into a defaults file either.
_ENV_OVERRIDES = (
    "NETWORK", "DISK_SIZE_GB", "RAM", "CPUS", "AUDIO", "PORTS", "SHARED",
    "CLIPBOARD", "USB", "SHARE_HOST_GPU", "SECURE_SHELL", "FULLSCREEN",
    "ASK_QUIT", "SSH", "SSHPORT", "DISK_SIZE",
)


@pytest.fixture(autouse=True)
def _isolate_config_home(tmp_path, monkeypatch):
    """Keep global defaults.cfg and env overrides out of every test."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdgcfg"))
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _form(directory) -> tui.Form:
    return tui.Form.load(str(directory))


def _session(form, interfaces=None) -> tui.Session:
    return tui.Session(form, interfaces or [])


def _select(session, key: str) -> None:
    target = configuration_schema.KEYS.index(key)
    step = ord("j") if target >= session.index else ord("k")
    while session.key != key:
        assert session.on_key(step) is None


# --- load -------------------------------------------------------------------

def test_p_opens_proxy_details_and_n_asks_for_the_next_proxy(tmp_path):
    session = _session(_form(tmp_path))
    assert session.on_key(ord("p")) is None
    assert session.mode == "proxy"
    assert session.on_key(ord("n")) == "proxy_next"
    assert session.on_key(27) is None
    assert session.mode == "nav"


def test_proxy_screen_reads_the_running_session(tmp_path):
    status = {
        "running": True,
        "current": {
            "url": "socks5://203.0.113.8:1080",
            "latency_ms": 180,
            "country": "DE",
            "country_name": "Germany",
            "exit_ip": "203.0.113.8",
            "colo": "FRA",
            "state": "durable",
            "uptime_s": 42,
            "ok": 9,
            "fail": 0,
        },
        "standbys": [{
            "url": "http://198.51.100.9:8080",
            "latency_ms": 240,
            "country": "US",
            "country_name": "United States",
            "exit_ip": "198.51.100.9",
            "colo": "EWR",
        }],
        "note": "",
    }
    (tmp_path / "proxy.status").write_text(
        __import__("json").dumps(status), encoding="utf-8",
    )
    lines = tui._proxy_lines(str(tmp_path))
    text = "\n".join(lines)
    assert "socks5://203.0.113.8:1080" in text
    assert "180 ms" in text
    assert "Germany" in text
    assert "203.0.113.8" in text
    assert "durable" in text
    assert "up 42s" in text
    assert "9 ok" in text
    assert "http://198.51.100.9:8080" in text
    assert "United States" in text


def test_missing_file_shows_defaults_and_writes_nothing(tmp_path):
    form = _form(tmp_path)
    assert form.existed is False
    assert not (tmp_path / "hypervisor.cfg").exists()
    assert form.values["RAM"] == "15%"
    assert form.values["Network"] == '"user"'
    assert form.values["Share_Host_GPU"] == "True"
    assert form.values["Secure_Shell"] == "False"
    assert form.values["Audio"] == "True"
    assert form.dirty is False
    assert form.tag("RAM") == "default"


def test_global_default_fills_a_key_the_file_does_not_set(tmp_path):
    defaults.set_key("ram", "8192")
    form = _form(tmp_path)
    assert form.values["RAM"] == "8192"
    assert form.tag("RAM") == "default"
    # An explicit file value still wins over the global default.
    (tmp_path / "hypervisor.cfg").write_text("RAM = 2048\n", encoding="utf-8")
    form = _form(tmp_path)
    assert form.values["RAM"] == "2048"
    assert form.tag("RAM") == "in file"


def test_env_override_is_not_a_configured_value(tmp_path, monkeypatch):
    # RAM=1024 would win at VM launch. The editor shows the file, not the env,
    # so a save cannot accidentally persist a one-shot override.
    monkeypatch.setenv("RAM", "1024")
    (tmp_path / "hypervisor.cfg").write_text("RAM = 2048\n", encoding="utf-8")
    form = _form(tmp_path)
    assert form.values["RAM"] == "2048"


def test_invalid_line_is_kept_and_marked(tmp_path):
    (tmp_path / "hypervisor.cfg").write_text("CPUs = lots\n", encoding="utf-8")
    form = _form(tmp_path)
    assert form.values["CPUs"] == "lots"
    assert "CPUs" in form.errors
    assert form.tag("CPUs") == "invalid"
    assert form.dirty is False  # still the text that is on disk


def test_legacy_keys_load_under_their_new_names(tmp_path):
    (tmp_path / "hypervisor.cfg").write_text(
        "ssh = true\ndisk_size = 200G\n", encoding="utf-8"
    )
    form = _form(tmp_path)
    assert form.values["Secure_Shell"] == "True"
    assert form.values["Disk_Size_GB"] == "200"
    assert "Secure_Shell" in form.explicit
    assert "Disk_Size_GB" in form.explicit


# --- editing ----------------------------------------------------------------

def test_set_value_stores_canonical_form_and_rejects_garbage(tmp_path):
    form = _form(tmp_path)
    ok, err = form.set_value("network", "none")
    assert ok, err
    assert form.values["Network"] == '"none"'
    assert form.dirty_keys == ["Network"]
    assert form.tag("Network") == "unsaved"

    ok, err = form.set_value("RAM", "lots")
    assert not ok
    assert "whole number" in err
    assert form.values["RAM"] == "15%"  # the previous value stays


def test_space_toggles_bools_and_cycles_network_and_shared(tmp_path):
    form = _form(tmp_path)
    session = _session(form, ["eno1"])
    assert session.key == "Share_Host_GPU"
    session.on_key(ord(" "))
    assert form.values["Share_Host_GPU"] == "False"
    session.on_key(ord(" "))
    assert form.values["Share_Host_GPU"] == "True"

    _select(session, "Network")
    session.on_key(ord(" "))
    assert form.values["Network"] == '"none"'
    session.on_key(9)  # Tab keeps cycling on Network
    assert form.values["Network"] == '"eno1"'
    session.on_key(curses.KEY_BTAB)
    assert form.values["Network"] == '"none"'

    _select(session, "Shared")
    assert form.values["Shared"] == "False"
    session.on_key(ord(" "))
    assert form.values["Shared"] == "True"
    session.on_key(ord(" "))
    assert form.values["Shared"] == "False"


def test_enter_edits_and_escape_discards(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "RAM")
    session.on_key(ord("e"))
    assert session.mode == "edit"
    assert session.buffer == "15%"
    session.on_key(21)  # Ctrl-U
    for ch in "8192":
        session.on_key(ord(ch))
    session.on_key(127)  # backspace
    session.on_key(ord("\n"))
    assert session.mode == "nav"
    assert form.values["RAM"] == "819"

    session.on_key(ord("e"))
    session.on_key(ord("x"))
    session.on_key(27)
    assert session.mode == "nav"
    assert form.values["RAM"] == "819"


def test_invalid_edit_stays_open_and_keeps_the_old_value(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "RAM")
    session.on_key(ord("e"))
    session.on_key(21)
    for ch in "lots":
        session.on_key(ord(ch))
    assert session.on_key(ord("\n")) is None
    assert session.mode == "edit"
    assert session.status_bad
    assert "RAM" in session.status
    assert form.values["RAM"] == "15%"


def test_enter_selects_the_value_so_typing_replaces_it(tmp_path):
    # Enter used to leave the cursor at the end, so "8192" became "15%8192"
    # and a path became "False/dev/sdb". The first key now replaces the value.
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "RAM")
    session.on_key(ord("\n"))
    assert session.mode == "edit"
    assert session.replace
    assert session.buffer == "15%"
    session.on_key(127)  # backspace clears the selection, it does not nibble one char
    assert session.buffer == ""
    assert session.replace is False
    session.on_key(27)

    session.on_key(ord("\n"))
    for ch in "8192":
        session.on_key(ord(ch))
    assert session.buffer == "8192"
    assert session.replace is False
    session.on_key(ord("\n"))
    assert form.values["RAM"] == "8192"

    _select(session, "Network")
    session.on_key(ord("\n"))
    assert session.buffer == "user"
    for ch in "none":
        session.on_key(ord(ch))
    session.on_key(ord("\n"))
    assert form.values["Network"] == '"none"'

    _select(session, "USB")
    session.on_key(ord("e"))
    for ch in "/dev/sdb":
        session.on_key(ord(ch))
    session.on_key(ord("\n"))
    assert form.values["USB"] == '"/dev/sdb"'


def test_read_key_decodes_arrows_curses_leaves_in_the_queue():
    if curses is None:
        pytest.skip("curses is not available")

    def once(seq, pending=None):
        data = list(seq)
        timeouts = []

        def getch():
            return data.pop(0) if data else -1

        def set_timeout(ms):
            timeouts.append(ms)

        return tui.read_key(getch, set_timeout, pending), timeouts

    assert once([curses.KEY_UP])[0] == curses.KEY_UP
    assert once([27, ord("["), ord("B")])[0] == curses.KEY_DOWN
    assert once([27, ord("O"), ord("B")])[0] == curses.KEY_DOWN
    assert once([27, ord("["), ord("D")])[0] == curses.KEY_LEFT
    assert once([27, ord("["), ord("1"), ord(";"), ord("5"), ord("B")])[0] == curses.KEY_DOWN
    assert once([27, ord("["), ord("3"), ord("~")])[0] == curses.KEY_DC
    assert once([27, ord("["), ord("Z")])[0] == curses.KEY_BTAB
    assert once([27, ord("O"), ord("P")])[0] == -1  # F1, not an edit key
    key, timeouts = once([27])
    assert key == 27
    assert timeouts == [40, -1]
    # A partial CSI is dropped, not replayed as "[".
    assert once([27, ord("[")])[0] == -1

    pending: list[int] = []
    data = [27, ord("q")]

    def getch():
        return data.pop(0) if data else -1

    assert tui.read_key(getch, lambda _ms: None, pending) == 27
    assert tui.read_key(getch, lambda _ms: None, pending) == ord("q")
    assert data == []


def test_digit_typeahead_replaces_a_number(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "CPUs")
    session.on_key(ord("4"))
    assert session.mode == "edit"
    assert session.buffer == "4"
    session.on_key(ord("\n"))
    assert form.values["CPUs"] == "4"


def test_d_resets_a_field_to_its_default(tmp_path):
    (tmp_path / "hypervisor.cfg").write_text("RAM = 8192\n", encoding="utf-8")
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "RAM")
    assert session.on_key(ord("d")) is None
    assert form.values["RAM"] == "15%"
    assert form.dirty
    assert "default" in session.status


def test_navigation_clamps_and_help_does_not_quit(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    assert session.on_key(curses.KEY_UP) is None
    assert session.index == 0
    session.on_key(ord("?"))
    assert session.mode == "help"
    session.on_key(curses.KEY_RESIZE)
    assert session.mode == "help"
    session.on_key(ord("j"))
    assert session.help_scroll == 1
    # q inside help closes the help. It does not quit the editor.
    assert session.on_key(ord("q")) is None
    assert session.mode == "nav"
    assert session.on_key(ord("q")) == "quit"


def test_quit_asks_only_when_there_are_unsaved_edits(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    form.set_value("Audio", "False")
    assert session.on_key(ord("q")) is None
    assert session.mode == "quit_ask"
    assert session.on_key(27) is None
    assert session.mode == "nav"
    assert form.dirty
    assert session.on_key(ord("q")) is None
    assert session.on_key(ord("n")) == "quit"
    # Discarding does not roll the form back; the process simply exits unsaved.
    assert form.values["Audio"] == "False"

    session.mode = "nav"
    assert session.on_key(ord("y")) is None  # y is not a nav command
    form.set_value("Audio", "False")
    session.on_key(ord("q"))
    assert session.on_key(ord("y")) == "save_quit"


def test_space_on_a_text_field_does_not_wipe_it(tmp_path):
    form = _form(tmp_path)
    session = _session(form)
    _select(session, "RAM")
    session.on_key(ord(" "))
    assert session.mode == "nav"
    assert form.values["RAM"] == "15%"
    assert "enter" in session.status


# --- save -------------------------------------------------------------------

def test_save_of_a_new_file_writes_only_changed_settings(tmp_path):
    form = _form(tmp_path)
    assert form.set_value("Audio", "False")[0]
    assert form.set_value("Ports", "22:49156, 1500:49157")[0]
    ok, message = tui.commit_save(form)
    assert ok, message
    assert message.startswith("Saved ")
    assert form.dirty is False
    text = (tmp_path / "hypervisor.cfg").read_text(encoding="utf-8")
    assert text.startswith("###")
    assert "Audio = False" in text
    assert 'Ports = "22:49156, 1500:49157"' in text
    # Untouched settings are not pinned, so later global defaults still apply.
    assert "\nRAM =" not in text
    assert (tmp_path / "hypervisor.cfg").stat().st_mode & 0o777 == 0o644

    ok, message = tui.commit_save(form)
    assert ok
    assert "No changes" in message


def test_save_roundtrips_through_the_loader(tmp_path):
    form = _form(tmp_path)
    assert form.set_value("Network", "none")[0]
    assert form.set_value("Secure_Shell", "True")[0]
    assert form.set_value("RAM", "4096")[0]
    assert form.set_value("USB", "/dev/sdb")[0]
    assert form.set_value("Shared", "/mnt/host/share")[0]
    form.save()
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.network == "none"
    assert hcfg.secure_shell is True
    assert hcfg.ram == 4096
    assert hcfg.usb == ["/dev/sdb"]
    assert hcfg.shared == "/mnt/host/share"


def test_save_rewrites_only_the_edited_line_of_a_full_file(tmp_path):
    configuration.HypervisorCfg.write(str(tmp_path), configuration.effective_defaults())
    path = tmp_path / "hypervisor.cfg"
    before = path.read_text(encoding="utf-8").split("\n")
    form = _form(tmp_path)
    assert form.set_value("Audio", "False")[0]
    form.save()
    after = path.read_text(encoding="utf-8").split("\n")
    diffs = [i for i, (old, new) in enumerate(zip(before, after)) if old != new]
    assert diffs == [before.index("Audio = True")]
    assert after[diffs[0]] == "Audio = False"
    assert len(before) == len(after)


def test_save_preserves_comments_vm_name_and_untouched_lines(tmp_path):
    path = tmp_path / "hypervisor.cfg"
    path.write_text(
        "### my note\n"
        "vm_name = codelis-debug\n"
        "ram = 2048  # guest memory\n",
        encoding="utf-8",
    )
    form = _form(tmp_path)
    assert form.set_value("RAM", "8192")[0]
    assert form.set_value("Secure_Shell", "True")[0]
    form.save()
    text = path.read_text(encoding="utf-8")
    assert "### my note" in text
    assert "vm_name = codelis-debug" in text
    assert "RAM = 8192  # guest memory" in text
    assert "ram = 2048" not in text
    assert "Secure_Shell = True" in text
    # The name the launcher reads survived the rewrite.
    assert configuration._vm_name_in_cfg(str(tmp_path)) == "codelis-debug"


def test_save_keeps_an_unedited_legacy_line_and_migrates_one_we_change(tmp_path):
    path = tmp_path / "hypervisor.cfg"
    path.write_text("ssh = true\nram = 2048\n", encoding="utf-8")
    form = _form(tmp_path)
    assert form.set_value("RAM", "4096")[0]
    form.save()
    text = path.read_text(encoding="utf-8")
    assert "ssh = true" in text
    assert "RAM = 4096" in text
    assert "Secure_Shell" not in text

    form = _form(tmp_path)
    assert form.values["Secure_Shell"] == "True"
    assert form.set_value("Secure_Shell", "False")[0]
    form.save()
    text = path.read_text(encoding="utf-8")
    assert "Secure_Shell = False" in text
    assert "ssh = true" not in text
    assert "RAM = 4096" in text


def test_save_is_refused_while_a_value_is_invalid(tmp_path):
    path = tmp_path / "hypervisor.cfg"
    original = "CPUs = lots\nRAM = 2048\n"
    path.write_text(original, encoding="utf-8")
    form = _form(tmp_path)
    assert form.set_value("RAM", "4096")[0]
    ok, message = tui.commit_save(form)
    assert not ok
    assert "CPUs" in message
    assert path.read_text(encoding="utf-8") == original

    assert form.set_value("CPUs", "4")[0]
    ok, message = tui.commit_save(form)
    assert ok, message
    text = path.read_text(encoding="utf-8")
    assert "CPUs = 4" in text
    assert "RAM = 4096" in text
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.cpus == 4
    assert hcfg.ram == 4096


def test_save_preserves_the_existing_file_mode(tmp_path):
    path = tmp_path / "hypervisor.cfg"
    path.write_text("RAM = 2048\n", encoding="utf-8")
    path.chmod(0o640)
    form = _form(tmp_path)
    assert form.set_value("RAM", "4096")[0]
    form.save()
    assert path.stat().st_mode & 0o777 == 0o640


def test_save_reports_an_unwritable_directory(tmp_path):
    missing = tmp_path / "no-such-dir"
    form = tui.Form.load(str(missing))
    assert form.set_value("Audio", "False")[0]
    ok, message = tui.commit_save(form)
    assert not ok
    assert "Could not save" in message
    assert not missing.exists()


def test_unedited_legacy_disk_size_is_not_rewritten(tmp_path):
    path = tmp_path / "hypervisor.cfg"
    path.write_text("disk_size = 200G\n", encoding="utf-8")
    form = _form(tmp_path)
    assert form.values["Disk_Size_GB"] == "200"
    ok, message = tui.commit_save(form)
    assert ok
    assert "No changes" in message
    assert path.read_text(encoding="utf-8") == "disk_size = 200G\n"


# --- dispatch ---------------------------------------------------------------

def test_bare_configure_needs_a_terminal(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    rc = cli.main(["--configure"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "terminal" in err.lower()
    assert "hypervisor.cfg" in err
    assert not (tmp_path / "hypervisor.cfg").exists()


def test_configure_help_describes_the_terminal_ui(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--configure", "--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "terminal UI" in out
    assert "hypervisor.cfg" in out
    assert "--set" in out
    assert "--status" in out

    rc = cli.main(["help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "terminal UI" in out
    assert "qvm --configure" in out


def test_configure_set_still_edits_global_defaults(tmp_path, monkeypatch):
    # The flag form is the global defaults surface, not the per-directory UI.
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--configure", "--set", "ram", "8192"])
    assert rc == 0
    assert defaults.load() == {"RAM": "8192"}
    assert not (tmp_path / "hypervisor.cfg").exists()


# --- the real screen, on a pty ----------------------------------------------

def test_tui_on_a_pty_toggles_secure_shell_and_saves(tmp_path):
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    path.write_text("RAM = 2048\nSecure_Shell = False\n", encoding="utf-8")
    presses = b"j" * configuration_schema.KEYS.index("Secure_Shell") + b" sq"
    rc, screen = _drive_pty(tmp_path, presses)
    assert rc == 0, screen
    text = path.read_text(encoding="utf-8")
    assert "Secure_Shell = True" in text
    assert "RAM = 2048" in text
    # The screen really drew the editor, not just the saver underneath it.
    assert "configure" in screen
    assert "Secure_Shell" in screen


def test_tui_on_a_pty_quit_does_not_touch_the_file(tmp_path):
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    original = "RAM = 2048\n"
    path.write_text(original, encoding="utf-8")
    before = path.stat().st_mtime_ns
    rc, screen = _drive_pty(tmp_path, b"q")
    assert rc == 0, screen
    assert path.read_text(encoding="utf-8") == original
    assert path.stat().st_mtime_ns == before


def _drive_pty(
    directory,
    keys: bytes,
    timeout: float = 5.0,
    rows: int = 40,
    cols: int = 120,
    cli_entry: bool = False,
) -> tuple[int, str]:
    """Run the editor on a pty, send `keys` once the UI is up, return (exit, screen).

    `cli_entry` drives `command_line_interface.main(["--configure"])` with the pty's
    cwd set to `directory`, which is what `qvm --configure` actually does. The default
    calls `configuration_tui.run` on that directory. Kills the child if it is still up.
    """
    import pty

    master, slave = pty.openpty()
    proc = None
    buf = b""
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
        env = os.environ.copy()
        env["PYTHONPATH"] = _LIBRARIES
        env["TERM"] = "xterm-256color"
        env["LANG"] = "C.UTF-8"
        env.pop("COLUMNS", None)
        env.pop("LINES", None)
        # The editor shortens Esc itself; don't let a parent value surprise it.
        env["ESCDELAY"] = "25"
        if cli_entry:
            script = (
                "import command_line_interface as cli; "
                "raise SystemExit(cli.main(['--configure']))"
            )
            argv = [sys.executable, "-u", "-c", script]
            cwd = str(directory)
        else:
            script = (
                "import sys, configuration_tui; "
                "raise SystemExit(configuration_tui.run(sys.argv[1]))"
            )
            argv = [sys.executable, "-u", "-c", script, str(directory)]
            cwd = None
        proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            cwd=cwd,
            close_fds=True,
        )
        os.close(slave)
        slave = -1
        buf = _read_until(master, b"configure", timeout=timeout)
        if proc.poll() is not None and b"configure" not in buf:
            return proc.returncode, buf.decode("utf-8", "replace")
        _write_all(master, keys)
        deadline = time.time() + timeout
        while proc.poll() is None and time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if master in ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        if proc.poll() is None:
            proc.kill()
        rc = proc.wait(timeout=2)
        return rc, buf.decode("utf-8", "replace")
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        if slave >= 0:
            os.close(slave)
        os.close(master)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except OSError:
            return
        if n <= 0:
            return
        view = view[n:]


def _read_until(master: int, needle: bytes, timeout: float) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline and needle not in buf:
        ready, _, _ = select.select([master], [], [], 0.1)
        if master not in ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _visible_screen(data: str, rows: int = 24, cols: int = 80) -> str:
    """Replay a curses byte stream into a grid, so a failure shows the UI not the escapes."""
    grid = [[" "] * cols for _ in range(rows)]
    y = x = 0

    def cup(row: int, col: int) -> None:
        nonlocal y, x
        y = max(0, min(rows - 1, row))
        x = max(0, min(cols - 1, col))

    i = 0
    n = len(data)
    while i < n:
        ch = data[i]
        if ch == "\x1b" and i + 1 < n and data[i + 1] == "[":
            i += 2
            params = ""
            while i < n and not (0x40 <= ord(data[i]) <= 0x7E):
                params += data[i]
                i += 1
            if i >= n:
                break
            final = data[i]
            i += 1
            nums = []
            for part in params.lstrip("?").split(";"):
                if part.isdigit():
                    nums.append(int(part))
            if final in ("H", "f"):
                cup((nums[0] - 1) if nums else 0, (nums[1] - 1) if len(nums) > 1 else 0)
            elif final == "d":  # VPA, row only
                cup((nums[0] - 1) if nums else 0, x)
            elif final == "G":  # HPA, column only
                cup(y, (nums[0] - 1) if nums else 0)
            elif final == "A":
                cup(y - (nums[0] if nums else 1), x)
            elif final == "B":
                cup(y + (nums[0] if nums else 1), x)
            elif final == "C":
                cup(y, x + (nums[0] if nums else 1))
            elif final == "D":
                cup(y, x - (nums[0] if nums else 1))
            elif final == "X":
                for col in range(x, min(cols, x + (nums[0] if nums else 1))):
                    grid[y][col] = " "
            elif final == "J" and (not nums or nums[0] == 2):
                grid = [[" "] * cols for _ in range(rows)]
                y = x = 0
            elif final == "K":
                mode = nums[0] if nums else 0
                if 0 <= y < rows:
                    if mode == 0:
                        for col in range(x, cols):
                            grid[y][col] = " "
                    elif mode == 1:
                        for col in range(0, min(x + 1, cols)):
                            grid[y][col] = " "
                    elif mode == 2:
                        grid[y] = [" "] * cols
            continue
        if ch == "\x1b" and i + 1 < n and data[i + 1] == "]":
            i += 2
            while i < n and data[i] != "\x07":
                if data[i] == "\x1b" and i + 1 < n and data[i + 1] == "\\":
                    i += 2
                    break
                i += 1
            if i < n and data[i] == "\x07":
                i += 1
            continue
        if ch == "\x1b":
            # ESC ( B / ESC ) 0 are charset shifts. ESC = / ESC > are keypad mode.
            i += 1
            if i < n and data[i] in "()":
                i += 2
            elif i < n:
                i += 1
            continue
        if ch == "\r":
            x = 0
        elif ch == "\n":
            y = min(rows - 1, y + 1)
        elif ch == "\b":
            x = max(0, x - 1)
        elif ch >= " " and y < rows and x < cols:
            grid[y][x] = ch
            x += 1
        i += 1
    return "\n".join("".join(row).rstrip() for row in grid).rstrip()


def _shown(screen: str, rows: int = 24, cols: int = 80) -> str:
    return _visible_screen(screen, rows, cols) + "\n---\n" + screen[-1500:]


_DOWN = b"\x1b[B"
_ENTER = b"\r"


def _type_value(text: str) -> bytes:
    """Enter (selects the whole value), the replacement, Enter (confirm)."""
    return _ENTER + text.encode("ascii") + _ENTER


def test_tui_on_a_pty_edits_every_field_with_real_arrow_keys(tmp_path, monkeypatch, capsys):
    """What a person actually does: Down between rows, Enter, type, save, then `qvm status`."""
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    monkeypatch.delenv("HYPERVISOR_VM_NAME", raising=False)
    path = tmp_path / "hypervisor.cfg"
    path.write_text("### keep me\nvm_name = codelis-demo\nRAM = 1024\n", encoding="utf-8")
    actions = {
        "Share_Host_GPU": b" ",
        "Network": _type_value("none"),
        "Proxy": _type_value("socks5://127.0.0.1:1080"),
        "Proxy_Kill_Switch": b" ",
        "Shared": _type_value("/mnt/share"),
        "Clipboard": b" ",
        "Secure_Shell": b" ",
        "Ports": _type_value("22:49400"),
        "Ssh_Forward_Port": _type_value("2222"),
        "USB": _type_value("/dev/sdb"),
        "Fullscreen": b" ",
        "Ask_Before_Quitting_Hypervisor": b" ",
        "RAM": _type_value("8192"),
        "CPUs": _type_value("4"),
        "Disk_Size_GB": _type_value("20%"),
        "Audio": b" ",
    }
    keys = b""
    last = len(configuration_schema.KEYS) - 1
    for index, key in enumerate(configuration_schema.KEYS):
        keys += actions[key]
        if index != last:
            keys += _DOWN
    keys += b"sq"
    rows, cols = 24, 80
    rc, screen = _drive_pty(tmp_path, keys, timeout=12.0, rows=rows, cols=cols, cli_entry=True)
    assert rc == 0, _shown(screen, rows, cols)
    text = path.read_text(encoding="utf-8")
    expected = (
        "### keep me\n"
        "vm_name = codelis-demo\n"
        "RAM = 8192\n"
        "Share_Host_GPU = False\n"
        'Network = "none"\n'
        'Proxy = "socks5://127.0.0.1:1080"\n'
        "Proxy_Kill_Switch = True\n"
        'Shared = "/mnt/share"\n'
        "Clipboard = True\n"
        "Secure_Shell = True\n"
        'Ports = "22:49400"\n'
        "Ssh_Forward_Port = 2222\n"
        'USB = "/dev/sdb"\n'
        "Fullscreen = True\n"
        "Ask_Before_Quitting_Hypervisor = True\n"
        "CPUs = 4\n"
        "Disk_Size_GB = 20%\n"
        "Audio = False\n"
    )
    assert text == expected, _shown(screen, rows, cols)
    assert "Saved" in screen
    assert "type to replace" in screen
    assert "8192" in screen

    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.share_host_gpu is False
    assert hcfg.network == "none"
    assert hcfg.proxy == "socks5://127.0.0.1:1080"
    assert hcfg.proxy_kill_switch is True
    assert hcfg.shared == "/mnt/share"
    assert hcfg.clipboard is True
    assert hcfg.secure_shell is True
    assert hcfg.ports == [(22, 49400)]
    assert hcfg.ssh_forward_port == 2222
    assert hcfg.usb == ["/dev/sdb"]
    assert hcfg.fullscreen is True
    assert hcfg.ask_before_quitting_hypervisor is True
    assert hcfg.ram == 8192
    assert hcfg.cpus == 4
    assert isinstance(hcfg.disk_size_gb, int) and hcfg.disk_size_gb > 0
    assert hcfg.audio is False

    again = tui.Form.load(str(tmp_path))
    assert not again.dirty
    assert again.values["RAM"] == "8192"
    assert again.values["Network"] == '"none"'
    assert again.values["Disk_Size_GB"] == "20%"
    assert again.values["Ports"] == '"22:49400"'

    monkeypatch.chdir(tmp_path)
    status_rc = cli.main(["status"])
    status = capsys.readouterr().out
    assert status_rc == 0, status
    assert "codelis-demo" in status
    assert "Network=none" in status
    assert "socks5://127.0.0.1:1080" in status
    assert "Proxy_Kill_Switch=True" in status
    assert "Shared=/mnt/share" in status
    assert "Secure_Shell=True" in status
    assert "Ports=22:49400" in status
    assert "USB=/dev/sdb" in status
    assert "Share_Host_GPU=False" in status
    assert "Clipboard=True" in status
    assert "Fullscreen=True" in status
    assert "Ask_Before_Quitting_Hypervisor=True" in status
    assert "RAM=8192" in status
    assert "CPUs=4" in status
    assert "Audio=False" in status
    assert "Disk_Size_GB=" in status


def test_tui_on_a_pty_ss3_arrow_moves_before_editing(tmp_path):
    """Application-cursor mode (the sequence xterm sends after keypad) moves one row."""
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    path.write_text("RAM = 1024\n", encoding="utf-8")
    # One SS3-down from Share_Host_GPU lands on Network. It must not edit the bool.
    keys = b"\x1bOB" + _type_value("none") + b"sq"
    rc, screen = _drive_pty(tmp_path, keys, timeout=8.0, rows=24, cols=80)
    assert rc == 0, _shown(screen)
    text = path.read_text(encoding="utf-8")
    assert 'Network = "none"' in text
    assert "Share_Host_GPU" not in text
    assert "RAM = 1024" in text


def test_tui_on_a_pty_escape_cancels_an_edit(tmp_path):
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    original = "RAM = 1024\n"
    path.write_text(original, encoding="utf-8")
    before = path.stat().st_mtime_ns
    downs = _DOWN * configuration_schema.KEYS.index("RAM")
    keys = downs + _ENTER + b"1" + b"\x1b" + b"q"
    rc, screen = _drive_pty(tmp_path, keys, timeout=8.0, rows=24, cols=80)
    assert rc == 0, _shown(screen)
    assert path.read_text(encoding="utf-8") == original
    assert path.stat().st_mtime_ns == before


def test_tui_on_a_pty_invalid_value_is_not_saved(tmp_path):
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    original = "RAM = 1024\n"
    path.write_text(original, encoding="utf-8")
    downs = _DOWN * configuration_schema.KEYS.index("RAM")
    # Enter, replace with garbage, Enter stays in the field, Esc drops it, q leaves.
    keys = downs + _ENTER + b"lots" + _ENTER + b"\x1b" + b"q"
    rc, screen = _drive_pty(tmp_path, keys, timeout=8.0, rows=24, cols=80)
    assert rc == 0, _shown(screen)
    assert path.read_text(encoding="utf-8") == original


def test_tui_on_a_pty_left_and_backspace_edit_inside_the_value(tmp_path):
    if curses is None or fcntl is None:
        pytest.skip("curses is not available")
    path = tmp_path / "hypervisor.cfg"
    path.write_text("RAM = 1024\n", encoding="utf-8")
    downs = _DOWN * configuration_schema.KEYS.index("RAM")
    # 8192, then Left onto the last digit, Backspace removes the 9 -> 812.
    keys = downs + _ENTER + b"8192" + b"\x1b[D" + b"\x7f" + _ENTER + b"sq"
    rc, screen = _drive_pty(tmp_path, keys, timeout=8.0, rows=24, cols=80)
    assert rc == 0, _shown(screen)
    assert "RAM = 812" in path.read_text(encoding="utf-8")
