"""checks.py - the die() helper and precondition checks.

Ported from libraries/common.sh's require_* functions. Each check raises
HypervisorError (caught in command_line_interface.py, printed as 'hypervisor: <msg>' and exit 1)
instead of calling `exit` directly, so the checks stay composable and testable.
"""

from __future__ import annotations

import os
import shutil


class HypervisorError(Exception):
    """A user-facing error. command_line_interface.py prints it and exits 1."""


def die(msg: str) -> "typing.NoReturn":  # noqa: F821
    raise HypervisorError(msg)


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def require_writable_dir(cfg) -> None:
    if not os.access(cfg.dir, os.W_OK):
        die(f"current directory is not writable: {cfg.dir}")


def require_qemu() -> None:
    for b in ("qemu-system-x86_64", "qemu-img"):
        if not _have(b):
            die(f"{b} missing -- sudo pacman -S qemu-full")


def require_ovmf(cfg) -> None:
    if not os.access(cfg.code, os.R_OK):
        die(f"OVMF_CODE missing: {cfg.code} -- sudo pacman -S edk2-ovmf")
    if not os.access(cfg.vars_tmpl, os.R_OK):
        die(f"OVMF_VARS template missing: {cfg.vars_tmpl} -- sudo pacman -S edk2-ovmf")


def require_kvm() -> None:
    if not os.path.exists("/dev/kvm"):
        die("/dev/kvm missing -- enable virtualization / load kvm modules")
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        die("/dev/kvm not accessible -- join the 'kvm' group and re-login")


def require_viewer() -> None:
    if not _have("remote-viewer"):
        die("remote-viewer missing -- sudo pacman -S virt-viewer")


# The standalone Rust virtiofsd ships its binary here, NOT on PATH (it is a
# libexec-style daemon). We accept either PATH or this well-known location.
_VIRTIOFSD_PATHS = ("/usr/lib/virtiofsd", "/usr/libexec/virtiofsd")


def virtiofsd_binary() -> str:
    """Path to the virtiofsd daemon binary, or '' if none is installed. Checks PATH
    first, then the well-known libexec locations the `virtiofsd` package uses."""
    on_path = shutil.which("virtiofsd")
    if on_path:
        return on_path
    for p in _VIRTIOFSD_PATHS:
        if os.path.exists(p):
            return p
    return ""


def require_virtiofsd() -> None:
    """The shared folder now rides virtiofs, which needs the virtiofsd daemon. Fail
    cleanly (not a crash) when --shared is requested but the daemon is absent."""
    if not virtiofsd_binary():
        die("virtiofsd missing (needed for the shared folder) -- sudo pacman -S virtiofsd")


def is_running(cfg) -> bool:
    """True if THIS instance's VM (the QEMU whose cwd IS cfg.dir) is alive.

    A bare `pgrep -x "$PROC"` is NOT enough: the comm is f"{slug}-vm" capped to the
    kernel's 15-char limit, so the slug is trimmed to 12 chars before "-vm" is appended
    (see configuration._proc_name). Two DIFFERENT dirs whose slugs share a 12-char prefix
    -- e.g. any two `codelis-claud*` instances -- collapse to the SAME comm 'codelis-clau-vm'.
    So do EVERY unrelated process that merely happens to carry that comm (a stale orphan QEMU
    from a since-deleted cwd, or anything named that way). A comm-only match then reports "VM
    already running" for a process that is NOT this instance's -- and because `stop`/teardown
    act by DIRECTORY/disk-path, they cannot kill that foreign process, so the launch deadlocks
    on "already running" forever. This is exactly the wedge codelis hit when a same-prefix or
    orphaned VM was present on the host.

    The fix: a match counts ONLY when the process's comm matches cfg.proc AND its working
    directory (/proc/<pid>/cwd) resolves to cfg.dir -- the SAME dir-is-identity rule
    vm_instances._running_instances and `stop` already use. Two VMs in two dirs (even with a
    colliding truncated comm) no longer see each other, and a foreign/stale comm can never
    stand in for this instance. Reads /proc directly (no pgrep dependency).
    """
    want_dir = os.path.realpath(cfg.dir)
    try:
        pids = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm != cfg.proc:
            continue
        # Recover the process cwd the same way vm_instances._pid_cwd does, INCLUDING the
        # kernel's " (deleted)" suffix strip so a VM whose dir was removed while it still
        # runs is still recognised as this instance's (its disk-path teardown can then act).
        try:
            target = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            continue
        deleted = " (deleted)"
        if target.endswith(deleted):
            target = target[: -len(deleted)]
        if os.path.realpath(target) == want_dir:
            return True
    return False


def require_not_running(cfg) -> None:
    if is_running(cfg):
        die(f"VM '{cfg.vm}' already running.")


def require_free_space(cfg, need_bytes: int = 8 * 1024 * 1024 * 1024) -> None:
    st = os.statvfs(cfg.dir)
    avail = st.f_bavail * st.f_frsize
    if avail < need_bytes:
        die(
            f"low free space in {cfg.dir}: {avail // 1024 // 1024} MiB avail, "
            f"need >= {need_bytes // 1024 // 1024} MiB"
        )
