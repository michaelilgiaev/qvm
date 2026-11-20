"""qvm --configure -- the terminal UI for this directory's hypervisor.cfg.

Bare `qvm --configure` edits ./hypervisor.cfg (the per-VM file). The global
defaults surface (`--set` / `--status` / `--reset`) is unchanged and covered in
test_configuration_hypervisor_defaults.py.

These tests drive Form and Session directly, so the decisions (what is loaded,
what an edit accepts, what a save rewrites) do not need a terminal. One test at
the bottom runs the real curses screen on a pty and types into it.
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
    while session.key != key:
        assert session.on_key(ord("j")) is None


# --- load -------------------------------------------------------------------

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


def _drive_pty(directory, keys: bytes, timeout: float = 5.0) -> tuple[int, str]:
    """Run configuration_tui.run on a pty, send `keys` once the UI is up, return
    (exit code, decoded screen). Kills the child if it is still running."""
    import pty

    master, slave = pty.openpty()
    proc = None
    buf = b""
    try:
        winsize = struct.pack("HHHH", 40, 120, 0, 0)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
        env = os.environ.copy()
        env["PYTHONPATH"] = _LIBRARIES
        env["TERM"] = "xterm-256color"
        env["LANG"] = "C.UTF-8"
        env.pop("COLUMNS", None)
        env.pop("LINES", None)
        # The editor shortens Esc itself; don't let a parent value surprise it.
        env.setdefault("ESCDELAY", "25")
        script = (
            "import sys, configuration_tui; "
            "raise SystemExit(configuration_tui.run(sys.argv[1]))"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(directory)],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        slave = -1
        buf = _read_until(master, b"configure", timeout=timeout)
        if proc.poll() is not None and b"configure" not in buf:
            return proc.returncode, buf.decode("utf-8", "replace")
        os.write(master, keys)
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
