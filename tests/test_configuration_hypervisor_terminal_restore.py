"""Terminal-restore on `qvm run` teardown -- the fix for the corrupted-tab bug.

THE BUG: after `qvm run`, tearing the VM down (close the window, or Ctrl-C during
boot) left the shell in -echo/-icanon -- typing showed nothing and the prompt rendered
mangled. ROOT CAUSE: remote-viewer links libvte, which puts the SHARED controlling tty
into raw mode; when it is killed on teardown VTE never restores it, and _launch had no
save/restore of its own, so the corruption survived into the shell.

THE FIX (two halves, both pinned here):
  1. SOURCE: remote-viewer is spawned with stdin=DEVNULL, so VTE has no controlling tty
     to corrupt in the first place.
  2. BELT-AND-BRACES: _launch snapshots termios up front (_tty_save) and restores it on
     EVERY teardown path via cleanup() (_tty_restore), recovering anything that still
     slips through.

These tests reproduce the raw-tty corruption on a real pty and assert the restore un-does
it, assert the headless (no-tty) path is a safe no-op, and pin the stdin=DEVNULL wiring so
the source-side half cannot silently regress.
"""

from __future__ import annotations

import os
import subprocess
import sys
import termios

import pytest

from hypervisor_helpers import make_cfg

import virtual_machine as vm


def _cfg(tmp_path, **overrides):
    return make_cfg(str(tmp_path), **overrides)


def _echo_on(fd: int) -> bool:
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)


def _canon_on(fd: int) -> bool:
    return bool(termios.tcgetattr(fd)[3] & termios.ICANON)


# --- the pure restore logic (reproduces the corruption, proves recovery) -----

def test_tty_restore_recooks_a_raw_terminal():
    # Reproduce the exact failure mode on a real pty: force the terminal RAW (as VTE
    # does), then assert _tty_restore puts ECHO/ICANON back -- i.e. the shell is usable
    # again. This is the corruption the user saw, and its fix, in miniature.
    import tty as ttymod
    master, slave = os.openpty()
    try:
        saved = (slave, termios.tcgetattr(slave))
        assert _echo_on(slave) and _canon_on(slave)        # sane to start
        ttymod.setraw(slave)                                # VTE-style corruption
        assert not _echo_on(slave) and not _canon_on(slave)  # now broken (no echo)
        vm._tty_restore(saved)                              # THE FIX
        assert _echo_on(slave) and _canon_on(slave)         # cooked again -> recovered
    finally:
        os.close(master)
        os.close(slave)


def test_tty_restore_is_noop_when_saved_is_none():
    # Headless / piped runs have no terminal to restore; restore(None) must be a silent
    # no-op (and must never raise), so `qvm run` under a pipe or in CI is safe.
    vm._tty_restore(None)  # no tty touched, no exception


def test_tty_save_returns_none_without_a_tty(monkeypatch):
    # When stdin is not a tty there is nothing to snapshot; _tty_save returns None so the
    # whole save/restore dance is skipped. Pin it so the teardown path stays exception-free
    # in non-interactive runs.
    class _NotTTY:
        def isatty(self):
            return False
    monkeypatch.setattr(vm.sys, "stdin", _NotTTY())
    assert vm._tty_save() is None


def test_tty_save_snapshots_a_real_tty(tmp_path):
    # On a real terminal, _tty_save returns (fd, attrs) that _tty_restore can consume.
    # Uses a pty as stdin so isatty() is true without depending on how pytest is launched.
    master, slave = os.openpty()

    class _TTY:
        def isatty(self):
            return True

        def fileno(self):
            return slave
    import types
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(vm.sys, "stdin", _TTY())
        saved = vm._tty_save()
        assert saved is not None
        fd, attrs = saved
        assert fd == slave
        assert isinstance(attrs, list)  # termios attribute list
    finally:
        monkeypatch.undo()
        os.close(master)
        os.close(slave)


# --- the source-side wiring: remote-viewer gets no controlling tty -----------

def test_remote_viewer_spawned_with_stdin_devnull(tmp_path, monkeypatch):
    # THE source-side guard. remote-viewer must be launched with stdin=DEVNULL so libvte
    # cannot grab our controlling terminal and leave it raw. We drive _launch with every
    # spawn faked, capture the remote-viewer Popen kwargs, and assert stdin is DEVNULL.
    calls = {}

    class _FakeProc:
        def __init__(self, argv, **kw):
            self.argv = argv
            self.kw = kw
            if argv and argv[0] == "remote-viewer":
                calls["viewer"] = kw
            self._alive = True

        def poll(self):
            return 0  # already exited -> _wait_any returns immediately, teardown runs

        def kill(self):
            self._alive = False

        def wait(self, timeout=None):
            return 0

    # Make the spice socket "appear" instantly so _launch proceeds to the viewer stage.
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)
    monkeypatch.setattr(vm, "_spawn_virtiofsd", lambda cfg: None)
    monkeypatch.setattr(vm.subprocess, "Popen", lambda argv, **kw: _FakeProc(argv, **kw))
    monkeypatch.setattr(vm.subprocess, "run", lambda *a, **k: None)
    # No live-config watcher thread in the test.
    monkeypatch.setattr(vm.configuration_watcher, "ConfigWatcher",
                        lambda *a, **k: type("W", (), {"start": lambda s: None,
                                                       "stop": lambda s: None})())
    monkeypatch.setattr(vm, "_maximize_window", lambda *a, **k: None)
    # Non-interactive stdin so the tty save/restore path is a no-op here.
    monkeypatch.setattr(vm.sys.stdin, "isatty", lambda: False, raising=False)

    cfg = _cfg(tmp_path, shared=False, ssh=False)
    vm._launch(cfg, ["qemu-system-x86_64"], port=None)

    assert "viewer" in calls, "remote-viewer was never spawned"
    assert calls["viewer"].get("stdin") is subprocess.DEVNULL, (
        "remote-viewer must be spawned with stdin=DEVNULL so libvte cannot corrupt "
        f"the controlling terminal; got {calls['viewer'].get('stdin')!r}")


def test_cleanup_restores_tty_on_teardown(tmp_path, monkeypatch):
    # End-to-end: on a real pty, a child that raws the terminal followed by _launch's
    # teardown must leave the terminal COOKED. We fake the children (one "raws" the pty
    # to model VTE), point _launch's stdin at the pty, and assert ECHO is back after
    # _launch returns.
    import tty as ttymod
    master, slave = os.openpty()

    class _TTY:
        def isatty(self):
            return True

        def fileno(self):
            return slave

    class _RawingProc:
        # Models remote-viewer/VTE: corrupts the shared tty, then "exits".
        def __init__(self, argv, **kw):
            if argv and argv[0] == "remote-viewer":
                ttymod.setraw(slave)  # dirty the terminal like VTE does

        def poll(self):
            return 0

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(vm.sys, "stdin", _TTY())
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)
    monkeypatch.setattr(vm, "_spawn_virtiofsd", lambda cfg: None)
    monkeypatch.setattr(vm.subprocess, "Popen", lambda argv, **kw: _RawingProc(argv, **kw))
    monkeypatch.setattr(vm.subprocess, "run", lambda *a, **k: None)  # skip real `stty`/pkill
    monkeypatch.setattr(vm.configuration_watcher, "ConfigWatcher",
                        lambda *a, **k: type("W", (), {"start": lambda s: None,
                                                       "stop": lambda s: None})())
    monkeypatch.setattr(vm, "_maximize_window", lambda *a, **k: None)

    try:
        assert _echo_on(slave)                 # sane before
        vm._launch(cfg := _cfg(tmp_path, shared=False, ssh=False),
                   ["qemu-system-x86_64"], port=None)
        assert _echo_on(slave), "terminal left in -echo after teardown (bug not fixed)"
    finally:
        os.close(master)
        os.close(slave)
