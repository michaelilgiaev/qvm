"""virtiofs shared-folder wiring -- the fix for the reported --shared/--ssh coupling.

The BUG: `--shared` only made the folder appear inside the ssh ISO variant, because
the share was mounted only as a side effect of the ssh bring-up service. Nothing on
the headed variant mounted it, so `--shared` silently did nothing there.

The FIX moves the transport to virtiofs and, on the HOST, spawns a `virtiofsd`
daemon whenever `shared` is set -- REGARDLESS of `ssh`. These tests pin that
decoupling at the pure command-builder level (`virtiofsd_argv`), plus the
`require_virtiofsd` precondition, so the coupling cannot silently come back.
"""

from __future__ import annotations

import pytest

from hypervisor_helpers import make_cfg

import virtual_machine as vm
import checks
from checks import HypervisorError


def _cfg(tmp_path, **overrides):
    return make_cfg(str(tmp_path), **overrides)


def test_no_daemon_when_shared_off(tmp_path):
    # shared off -> no daemon command at all (nothing to export).
    cfg = _cfg(tmp_path, shared=False, ssh=False)
    assert vm.virtiofsd_argv(cfg) == []


def test_daemon_spawned_when_shared_on_regardless_of_ssh(tmp_path):
    # THE regression guard: the daemon (== the share actually working) depends ONLY
    # on shared, never on ssh. Both ssh=False and ssh=True must produce the daemon,
    # pointed at the same host dir and the same vhost-user socket.
    for ssh in (False, True):
        cfg = _cfg(tmp_path, shared=True, ssh=ssh)
        argv = vm.virtiofsd_argv(cfg)
        assert argv, f"expected a virtiofsd command with ssh={ssh}"
        joined = " ".join(argv)
        assert "virtiofsd" in joined                # the daemon binary is invoked
        assert cfg.shared_path in joined            # exports the host share dir
        assert cfg.virtiofs_sock in joined          # on the vhost-user socket QEMU reads


def test_daemon_runs_rootless_no_sudo(tmp_path):
    # THE sudo-is-bugged-on-host guard. sudo unreliability was causing `sudo virtiofsd`
    # to never start, so the socket never appeared and QEMU died "Failed to connect ...
    # No such file or directory". virtiofsd must therefore run ROOTLESS: no sudo may
    # appear anywhere in the argv, and the real binary must be argv[0].
    cfg = _cfg(tmp_path, shared=True)
    argv = vm.virtiofsd_argv(cfg)
    assert "sudo" not in argv, f"virtiofsd must run rootless (no sudo); got {argv!r}"
    assert argv[0].endswith("virtiofsd"), f"binary must be argv[0]; got {argv[0]!r}"


def test_daemon_needs_no_socket_group_when_rootless(tmp_path):
    # Rootless -> the socket is owned by the invoking user and the (same-user, non-root)
    # QEMU opens it directly. No --socket-group hand-off is needed or emitted, and the
    # builder takes no group argument any more.
    cfg = _cfg(tmp_path, shared=True)
    argv = vm.virtiofsd_argv(cfg)
    assert not any(a.startswith("--socket-group") for a in argv)


def test_daemon_squashes_guest_ids_to_host_owner(tmp_path, monkeypatch):
    # THE writable-share guard. Rootless virtiofsd cannot setfsuid() to guest
    # credentials, so a guest write stamped with an id the host user does NOT hold
    # is rejected with EPERM -- the share mounts rw yet every write fails. This bit
    # an azzio guest on uid 1000 / PRIMARY gid 998 (autologin): gid 998 is not a gid
    # the host user (gid 1000) can act as. The fix squashes the WHOLE guest id range
    # onto our real host uid/gid via --translate-uid/--translate-gid, so any guest id
    # collapses to one we own and the write always lands. Pin it so a future edit
    # cannot silently drop the flags and re-lock the share.
    monkeypatch.setattr(vm.os, "getuid", lambda: 1000)
    monkeypatch.setattr(vm.os, "getgid", lambda: 998)
    cfg = _cfg(tmp_path, shared=True)
    argv = vm.virtiofsd_argv(cfg)
    _ALL = 0xFFFFFFFF  # full 32-bit id range -> no guest id (998 included) escapes
    assert f"--translate-uid=squash-guest:0:1000:{_ALL}" in argv, argv
    assert f"--translate-gid=squash-guest:0:998:{_ALL}" in argv, argv


def test_daemon_squash_tracks_the_real_launching_user(tmp_path, monkeypatch):
    # The squash target is our ACTUAL uid/gid (os.getuid/os.getgid), never a
    # hardcoded 1000 -- so whoever launches the daemon, guest writes land as that
    # user's own ids. Pin different ids and prove they flow through verbatim.
    monkeypatch.setattr(vm.os, "getuid", lambda: 4242)
    monkeypatch.setattr(vm.os, "getgid", lambda: 4343)
    argv = vm.virtiofsd_argv(_cfg(tmp_path, shared=True))
    assert any(a.startswith("--translate-uid=squash-guest:0:4242:") for a in argv), argv
    assert any(a.startswith("--translate-gid=squash-guest:0:4343:") for a in argv), argv


def test_daemon_exports_custom_path(tmp_path):
    custom = "/mnt/host/project"
    cfg = _cfg(tmp_path, shared=custom)
    assert custom in " ".join(vm.virtiofsd_argv(cfg))


def test_require_virtiofsd_raises_when_binary_absent(tmp_path, monkeypatch):
    # When --shared is requested but no virtiofsd binary exists anywhere (not on
    # PATH, not at the well-known libexec paths), the check must fail CLEANLY
    # (HypervisorError -> 'qvm: ...' exit 1), never crash.
    monkeypatch.setattr(checks.shutil, "which", lambda _b: None)
    monkeypatch.setattr(checks.os.path, "exists", lambda _p: False)
    with pytest.raises(HypervisorError):
        checks.require_virtiofsd()


def test_require_virtiofsd_passes_when_binary_on_path(tmp_path, monkeypatch):
    # Present on PATH -> no error, and the resolved path is what which() returned.
    monkeypatch.setattr(checks.shutil, "which",
                        lambda b: "/usr/bin/virtiofsd" if b == "virtiofsd" else None)
    checks.require_virtiofsd()  # must not raise
    assert checks.virtiofsd_binary() == "/usr/bin/virtiofsd"


def test_virtiofsd_binary_falls_back_to_libexec(tmp_path, monkeypatch):
    # Not on PATH but present at the well-known /usr/lib location -> found there.
    monkeypatch.setattr(checks.shutil, "which", lambda _b: None)
    monkeypatch.setattr(checks.os.path, "exists",
                        lambda p: p == "/usr/lib/virtiofsd")
    assert checks.virtiofsd_binary() == "/usr/lib/virtiofsd"
