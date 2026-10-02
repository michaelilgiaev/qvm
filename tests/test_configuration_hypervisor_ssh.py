"""qvm ssh -- the connect helper that ALWAYS restores the local terminal.

The bug this pins: a hand-typed `ssh -p 49155 main@localhost` into the guest puts
the LOCAL controlling terminal into raw mode for the session, and on an abnormal
teardown (connection reset, remote pty killed) the ssh client never restores the
saved termios -- leaving the tab in -echo/-icanon ("typing makes the bash line
disappear"). `qvm ssh` wraps ssh and restores termios + `stty sane` in a
finally on EVERY exit path, so the terminal is cooked again no matter how ssh dies.

Two units are pinned here:
  * ssh_argv() -- PURE: builds the ssh command (port, user@host, extra args). No spawn.
  * do_ssh()   -- restores the saved terminal state even when the ssh child raises
                  (the abnormal-teardown path). We assert the restore runs regardless.
"""

from __future__ import annotations

from hypervisor_helpers import make_cfg

import ssh_connect as sc


def _cfg(tmp_path, **cfg_overrides):
    return make_cfg(str(tmp_path), **cfg_overrides)


# --- ssh_argv (pure) --------------------------------------------------------
def test_ssh_argv_targets_the_forwarded_port_and_guest_user(tmp_path):
    cfg = _cfg(tmp_path, ssh=True, ssh_guest_to_host_port_forward=49155)
    argv = sc.ssh_argv(cfg, user="main", port=49155, extra=[])
    assert argv[0] == "ssh"
    # -p <port> pair present
    assert argv[argv.index("-p") + 1] == "49155"
    # connects to the guest user at the loopback the port is forwarded on
    assert "main@localhost" in argv


def test_ssh_argv_appends_user_extra_args_verbatim(tmp_path):
    cfg = _cfg(tmp_path, ssh=True)
    argv = sc.ssh_argv(cfg, user="main", port=2222, extra=["-v", "uptime"])
    # extra args ride AFTER the destination so `qvm ssh -- uptime` runs a command
    assert argv[-2:] == ["-v", "uptime"]
    assert argv[argv.index("-p") + 1] == "2222"


# --- do_ssh: terminal is ALWAYS restored ------------------------------------
def test_do_ssh_restores_terminal_after_a_normal_session(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, ssh=True)
    restored = []
    _install_fake_tty(monkeypatch, restored, child_raises=False)

    sc.do_ssh(cfg, extra=[])

    assert restored == ["restored"], "terminal must be restored after a clean session"


def test_do_ssh_restores_terminal_even_when_ssh_dies_abnormally(tmp_path, monkeypatch):
    """The regression that matters: the ssh child blows up mid-session (connection
    reset / killed pty). The terminal MUST still be restored -- otherwise the tab is
    left in -echo, which is exactly the reported bug."""
    cfg = _cfg(tmp_path, ssh=True)
    restored = []
    _install_fake_tty(monkeypatch, restored, child_raises=True)

    # do_ssh must not let the child's failure escape without restoring the terminal.
    sc.do_ssh(cfg, extra=[])

    assert restored == ["restored"], "terminal must be restored on the abnormal path too"


def test_do_ssh_restores_terminal_then_reraises_an_unexpected_error(tmp_path, monkeypatch):
    """A non-KeyboardInterrupt failure from the ssh spawn (e.g. OSError: ssh binary
    vanished) must STILL restore the terminal via the finally, then propagate -- the
    terminal is never left raw, but an unexpected error is not silently swallowed."""
    import pytest
    cfg = _cfg(tmp_path, ssh=True)
    restored = []
    _install_fake_tty(monkeypatch, restored, child_raises=False)

    def _boom(argv, *a, **k):
        raise OSError("ssh vanished")
    monkeypatch.setattr(sc.subprocess, "run", _boom)

    with pytest.raises(OSError):
        sc.do_ssh(cfg, extra=[])
    assert restored == ["restored"], "terminal must be restored even when the error propagates"


def _install_fake_tty(monkeypatch, restored, *, child_raises):
    """Pin the tty plumbing so the test is deterministic and headless:
      * stdin is a tty, tcgetattr returns a sentinel, tcsetattr records the restore,
      * the ssh subprocess either returns cleanly or raises (abnormal teardown)."""
    import subprocess

    class _FakeStdin:
        def fileno(self):
            return 0

        def isatty(self):
            return True

    monkeypatch.setattr(sc.sys, "stdin", _FakeStdin())
    monkeypatch.setattr(sc, "_tty_getattr", lambda fd: "SAVED")
    monkeypatch.setattr(sc, "_tty_restore",
                        lambda fd, saved: restored.append("restored"))

    def _fake_run(argv, *a, **k):
        if child_raises:
            raise KeyboardInterrupt  # models Ctrl-C / a killed session
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(sc.subprocess, "run", _fake_run)
