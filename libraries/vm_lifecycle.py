"""vm_lifecycle.py - the status / stop subcommands and the view/stop target resolver.

Split out of virtual_machine.py (which kept growing past the module size budget): `status`
(report a VM's state) and `stop` (power it off cleanly and synchronously), plus the
_target_cfg / _target_cfg_and_pid helpers that let `view`/`stop` act on a VM the user is
not cd'd into. virtual_machine re-exports these so vm.do_status / vm.do_stop still resolve
at their call sites in command_line_interface, and do_view (which stays in virtual_machine
because it shares _spawn_viewer with run) still finds _target_cfg. The flat sibling
import below mirrors the rest of the modules (see configuration.py for the full rationale).
"""

from __future__ import annotations

import os
import signal
import subprocess
import time

# Flat sibling imports: the modules live directly in libraries/ (no package).
from checks import is_running  # noqa: E402  (after virtual_machine's sys.path bootstrap)
from configuration import Config, select_ssh_port  # noqa: E402
from vm_instances import _resolve_target  # noqa: E402


# --- status / stop -----------------------------------------------------------
def do_status(cfg: Config) -> None:
    running = "RUNNING" if is_running(cfg) else "stopped"
    hcfg = cfg.hcfg
    port = select_ssh_port(cfg) if hcfg.secure_shell else None
    iso = cfg.find_iso()
    disk_name = os.path.basename(cfg.disk)
    vars_name = os.path.basename(cfg.vars)
    disk = f"{disk_name}  (qcow2)" if os.path.isfile(cfg.disk) else "(none - not installed)"
    uefi = f"{vars_name}  (UEFI NVRAM)" if os.path.isfile(cfg.vars) else "(none)"
    ssh = f"localhost:{port} -> guest :22" if port is not None else "disabled (Secure_Shell=False)"
    shared = cfg.shared_path or "(none)"
    usb = " ".join(hcfg.usb) if hcfg.usb else "(none)"
    ports = ", ".join(f"{g}:{h}" for g, h in hcfg.ports) if hcfg.ports else "(none)"
    print(f"VM:        {cfg.vm}   (process: {cfg.proc})")
    print(f"Directory: {cfg.dir}")
    print(f"State:     {running}")
    print(f"Disk:      {disk}")
    print(f"UEFI vars: {uefi}")
    print(f"Shared:    {shared}")
    print(f"ISO:       {iso or '(none in dir)'}")
    print(f"SSH:       {ssh}")
    print(f"Toggles:   Share_Host_GPU={hcfg.share_host_gpu}  Network={hcfg.network}  "
          f"Shared={hcfg.shared}  Clipboard={hcfg.clipboard}  Secure_Shell={hcfg.secure_shell}  "
          f"Ports={ports}  USB={usb}  Fullscreen={hcfg.fullscreen}  "
          f"Ask_Before_Quitting_Hypervisor={hcfg.ask_before_quitting_hypervisor}")
    print(f"Hardware:  RAM={cfg.ram} CPUs={cfg.cpus} "
          f"Disk_Size_GB={cfg.disk_size_gb} Audio={hcfg.audio}")


def _target_cfg(cfg: Config, arg: str) -> Config:
    """The Config a `view`/`stop` invocation should act on. With NO arg it is the cwd
    cfg the caller passed (the historic behaviour every existing call site -- and the
    codelis launcher's bare `qvm stop` -- relies on). With a PID or name it is a
    fresh Config rooted at the directory that instance runs in, so we can view/stop a VM
    the user is not cd'd into."""
    if not arg:
        return cfg
    inst = _resolve_target(arg)
    return Config.from_dir(inst["dir"])


def _target_cfg_and_pid(cfg: Config, arg: str) -> "tuple[Config, int | None]":
    """Like _target_cfg, but also returns the RESOLVED pid (or None for the bare cwd
    case). stop uses the pid to kill the exact process `_resolve_target` matched --
    authoritative even when the VM's dir was deleted and the comm-derived match would
    otherwise be unreliable. view ignores the pid (it only needs the cfg for sockets)."""
    if not arg:
        return cfg, None
    inst = _resolve_target(arg)
    return Config.from_dir(inst["dir"]), inst["pid"]


def _pid_alive(pid: int) -> bool:
    """True if `pid` exists (signal 0 probes without killing)."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # It exists, we just may not own it -- treat as alive.
        return True


def do_stop(cfg: Config, arg: str = "") -> None:
    """Power a VM off, CLEANLY and synchronously. With no argument, THIS directory's VM;
    with a PID or a VM name, whichever running instance that resolves to.

    This used to only SIGTERM QEMU and return at once, leaving the VM's virtiofsd daemon
    to be reaped ASYNCHRONOUSLY by the backgrounded `qvm run` process -- so its
    "[INFO virtiofsd] Client disconnected, shutting down" line printed to the terminal
    AFTER the prompt came back, and `stop` looked hung. We now (1) SIGTERM QEMU, (2)
    directly kill this VM's virtiofsd (matched by its per-dir socket, so no other VM's
    daemon is touched) so its teardown happens HERE under our control instead of leaking
    out later, and (3) WAIT (bounded) for QEMU to actually exit, escalating to SIGKILL if
    it overstays -- so the command returns only once the VM is truly down. `run`'s own
    cleanup() still runs and is idempotent, so double-killing is harmless."""
    cfg, pid = _target_cfg_and_pid(cfg, arg)

    # "Running?" check. When we resolved a concrete pid (arg was a name/pid), trust THAT
    # pid's liveness -- it is authoritative even for a VM whose dir was deleted, where the
    # comm-based is_running(cfg) could disagree. With no pid (bare cwd stop) fall back to
    # the comm match, exactly as before.
    running = _pid_alive(pid) if pid is not None else is_running(cfg)
    if not running:
        print(f"VM '{cfg.vm}' is not running.")
        return

    # SIGTERM the QEMU process. Kill it BOTH by the resolved pid (exact, dir-independent)
    # and by comm (covers the bare-cwd path where pid is None). The pid kill is what makes
    # a deleted-dir zombie actually die: its recomputed comm may not match, but the pid does.
    if pid is not None:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    subprocess.run(["pkill", "-TERM", "-x", cfg.proc],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Kill THIS VM's virtiofsd now (its stdout was the launcher's terminal). Matched on
    # the per-VM socket path so only this VM's daemon dies. Silent -- we own its exit here.
    subprocess.run(["pkill", "-TERM", "-f", f"virtiofsd.*{cfg.virtiofs_sock}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait (bounded ~5s) for QEMU to go, so `stop` is synchronous: the prompt returns
    # only after the VM is actually down, never with a stray daemon message still to come.
    # Liveness is judged by the same authoritative source used above.
    def _still_up() -> bool:
        return _pid_alive(pid) if pid is not None else is_running(cfg)
    for _ in range(50):
        if not _still_up():
            break
        time.sleep(0.1)
    else:
        # Overstayed the grace period -- force it (and its daemon) down.
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        subprocess.run(["pkill", "-KILL", "-x", cfg.proc],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-KILL", "-f", f"virtiofsd.*{cfg.virtiofs_sock}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Powered off VM '{cfg.vm}'.")
