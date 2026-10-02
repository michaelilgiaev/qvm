"""ssh_connect.py - the `qvm ssh` connect helper.

Split out of virtual_machine.py (which was pushing the 750-line limit) because the
connect helper is a self-contained unit: build the ssh command, then run it while
guaranteeing the local terminal is restored on every exit path.

WHY THIS EXISTS. A hand-typed `ssh -p <port> main@localhost` into the guest puts the
LOCAL controlling terminal into raw mode for the session; on an abnormal teardown
(connection reset, killed pty) the ssh client never restores the saved termios, so
the tab is left in -echo/-icanon and typing no longer echoes ("the bash line
disappears"). do_ssh snapshots termios before ssh and restores it (plus `stty sane`)
in a finally on EVERY exit path, so the terminal is never left broken.
"""

from __future__ import annotations

import os
import subprocess
import sys

# Flat sibling imports: the modules live directly in libraries/ (no package).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checks import die  # noqa: E402  (after the sys.path bootstrap above)
from configuration import Config, select_ssh_port  # noqa: E402


def ssh_argv(cfg: Config, *, user: str, port: int, extra: list[str]) -> list[str]:
    """The ssh command that connects to THIS VM's guest over the forwarded host
    port. PURE (no spawn) so it can be pinned in tests.

    The guest's :22 is forwarded to localhost:<port> on the host (see _net_args'
    hostfwd), so we always target user@localhost on that port. Any `extra` args the
    caller passed (e.g. `qvm ssh -- uptime`, or `-v`) ride verbatim AFTER the
    destination, matching ssh's own `ssh host command` grammar. A fresh guest's host
    key changes every reinstall, so we don't pollute ~/.ssh/known_hosts with an
    entry that will later mismatch -- StrictHostKeyChecking=accept-new trusts it once
    and UserKnownHostsFile=/dev/null keeps the host file clean."""
    return [
        "ssh",
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=/dev/null",
        f"{user}@localhost",
        *extra,
    ]


def _tty_getattr(fd: int):
    """Save the terminal's current attributes (or None when fd is not a tty). Thin
    wrapper so do_ssh's restore path is deterministically testable."""
    import termios
    return termios.tcgetattr(fd)


def _tty_restore(fd: int, saved) -> None:
    """Restore the saved terminal attributes AND run `stty sane` as a belt-and-braces
    reset. Thin wrapper so tests can pin it."""
    import termios
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    except (termios.error, OSError):
        pass
    # `stty sane` also re-cooks anything tcsetattr's snapshot didn't cover (e.g. an
    # alt-screen / bracketed-paste mode the guest shell left on). Best-effort.
    subprocess.run(["stty", "sane"], stdin=sys.stdin,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def do_ssh(cfg: Config, extra: list[str]) -> None:
    """`qvm ssh [-- args]` -- ssh into this VM's guest, ALWAYS leaving the
    local terminal cooked afterward. This is the fix for the reported bug: a bare
    `ssh -p <port> main@localhost` puts the controlling terminal into raw mode for
    the session, and an abnormal teardown (connection reset, killed pty) leaves it
    in -echo/-icanon so typing no longer echoes. We snapshot termios before ssh and
    restore it (plus `stty sane`) in a finally on EVERY exit path -- normal logout,
    Ctrl-C, or a dropped connection -- so the tab is never left broken.

    Requires ssh=true for this VM (that is what forwards guest :22 to the host)."""
    hcfg = cfg.hcfg
    if not hcfg.secure_shell:
        die("ssh is disabled for this VM (Secure_Shell=False in hypervisor.cfg). "
            "Enable it and reboot the VM, then: qvm ssh")
    port = select_ssh_port(cfg)
    # The guest login name inside the VM. Defaults to the Azzio guest account
    # (`main`); overridable for a differently-named guest, mirroring do_share_offline.
    user = os.environ.get("GUEST_USER", "main")
    argv = ssh_argv(cfg, user=user, port=port, extra=extra)

    fd = sys.stdin.fileno() if sys.stdin.isatty() else None
    saved = _tty_getattr(fd) if fd is not None else None
    print(f"ssh -> {user}@localhost:{port}  (guest :22)", file=sys.stderr)
    try:
        subprocess.run(argv)
    except KeyboardInterrupt:
        pass  # Ctrl-C during the session: fall through to restore the terminal.
    finally:
        if fd is not None and saved is not None:
            _tty_restore(fd, saved)
