"""Host-wide hypervisor VM enumeration -- the `qvm ls` backend.

Split out of virtual_machine.py: everything here is about discovering EVERY running
hypervisor VM on the host (system-wide), which is a different concern from the
single-VM boot/attach/teardown lifecycle that virtual_machine.py owns. Keeping it
here holds virtual_machine.py's size down and isolates the /proc-scanning logic.

The one impure edge (reading /proc) is factored into _scan_proc_table / _pid_cwd so
the record-building logic (_running_instances) stays PURE and unit-testable with a
fake process table. virtual_machine.py re-imports these names, so `vm.do_ls`,
`vm._running_instances`, `vm._cfg_ssh_port` and `vm._pid_cwd` all still resolve for
the CLI dispatch and the existing tests.
"""

from __future__ import annotations

import os
import sys

# Flat sibling imports: the modules live directly in libraries/ (no package).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checks import die  # noqa: E402
from configuration import (  # noqa: E402
    DEFAULT_SSH_FORWARD_PORT, GUEST_SSH_PORT, _HYPERVISOR_CFG_NAME, parse_conf_text,
    _slugify, _vm_name_in_cfg, _migrate_legacy_keys,
)
from configuration_schema import coerce_all  # noqa: E402


def _scan_proc_table() -> list:
    """Read the LIVE process table as a list of (pid, comm) pairs from /proc.

    Impure (touches /proc), factored out so _running_instances -- the logic that
    turns the table into VM records -- stays PURE and unit-testable with a fake
    table. A vanished pid between listdir and read is skipped (a race is harmless)."""
    out = []
    try:
        pids = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return out
    for pid in pids:
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        out.append((int(pid), comm))
    return out


def _pid_cwd(pid: int) -> str:
    """The working directory of `pid` (readlink /proc/<pid>/cwd), or '' if gone.
    A VM's dir IS its identity, so this is how `ls` recovers WHERE each VM lives.

    If the dir was DELETED while the VM still runs, the kernel makes the symlink read
    back as "<dir> (deleted)". We STRIP that suffix so the VM keeps slugging to its
    real name ("codelis", not "codelis-deleted"): with the clean basename the proc
    name `stop` recomputes (`_proc_name(_slugify(basename))`) still equals the LIVE
    comm, so `stop <name>`/`stop <pid>` can actually kill the zombie instead of
    reporting "not running". (Without this strip the recomputed comm was the truncated
    "codelis-dele-vm", which never matched the running "codelis-vm".)"""
    try:
        target = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return ""
    # The kernel appends this exact literal for an unlinked cwd. A real directory path
    # never ends in it, so stripping is safe.
    suffix = " (deleted)"
    if target.endswith(suffix):
        target = target[: -len(suffix)]
    return target


def _cfg_ssh_port(directory: str) -> "int | None":
    """The forwarded ssh port a VM dir advertises: read Secure_Shell + the base from its
    hypervisor.cfg (NOT select_ssh_port, which would BUMP past the now-busy port a running VM
    already holds and report a wrong number). The base is, in order: an explicit "22:host" map
    in Ports, else the Ssh_Forward_Port key (the manager's floor -- so a VM installed with a
    custom `--ssh=PORT` reports PORT, not the built-in default), else DEFAULT_SSH_FORWARD_PORT.
    None when ssh is off or the cfg is unreadable. Goes through the SAME legacy migration +
    schema coercion as a real load, so a legacy `ssh = true` + `ssh_guest_to_host_port_forward
    = N` cfg (and a codelis-written one) still reports its port. PURE except for the one read.

    NOTE (bare `qvm run`): the package does not persist the bump-chosen port back to the
    cfg, so a non-codelis VM that bumped to base+1 still advertises the base here -- the same
    approximation the pre-manager code had. codelis pins the real port into the cfg before boot
    (pin_ssh_port), so codelis-driven instances -- the multi-instance case -- report exactly."""
    path = os.path.join(directory, _HYPERVISOR_CFG_NAME)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = parse_conf_text(fh.read())
    except OSError:
        return None
    coerced, _errors = coerce_all(_migrate_legacy_keys(raw))
    if not coerced.get("Secure_Shell"):
        return None
    for guest, host in coerced.get("Ports", []):
        if guest == GUEST_SSH_PORT:
            return host
    return coerced.get("Ssh_Forward_Port") or DEFAULT_SSH_FORWARD_PORT


def _running_instances(proc_table: "list | None" = None) -> list:
    """Every RUNNING hypervisor VM on the host, as a list of dicts
    {vm, pid, dir, ssh_port} sorted by vm name. PURE given a proc_table (defaults to
    the live one via _scan_proc_table) so tests drive it with a fake table.

    A hypervisor VM's QEMU is launched `-name {vm},process={proc}` where proc is
    f"{slug}-vm" capped to 15 chars, so its comm ENDS in "-vm" (the cap never eats the
    suffix: "-vm" is 3 chars, well inside 15). We match those, recover each VM's dir
    from /proc/<pid>/cwd, derive the vm name from the dir basename (authoritative --
    the 15-char comm may be truncated), and read the ssh port from that dir's cfg."""
    if proc_table is None:
        proc_table = _scan_proc_table()
    instances = []
    for pid, comm in proc_table:
        if not comm.endswith("-vm"):
            continue
        directory = _pid_cwd(pid)
        if not directory:
            continue
        # The authoritative name matches Config.from_dir: an explicit vm_name in the dir's
        # hypervisor.cfg wins, else the dir basename. This is why codelis's fixed
        # 'venv/codelis' dir still shows as 'codelis-claudedebug' in `ls` and resolves under
        # that name for `stop`/`view` -- codelis writes vm_name into the instance cfg.
        # Enumeration reads the cfg (per-dir), NEVER the env, so one shell's
        # HYPERVISOR_VM_NAME can't stamp itself onto every VM listed here.
        override = _vm_name_in_cfg(directory)
        vm_name = _slugify(override) if override else _slugify(os.path.basename(directory))
        instances.append({
            "vm": vm_name,
            "pid": pid,
            "dir": directory,
            "ssh_port": _cfg_ssh_port(directory),
        })
    return sorted(instances, key=lambda i: (i["vm"], i["pid"]))


def do_ls(cfg) -> None:
    """List every running hypervisor VM on the host (system-wide, NOT just this dir).
    cfg is accepted for a uniform subcommand signature but unused -- `ls` is global."""
    instances = _running_instances()
    if not instances:
        print("No qvm VMs are running.")
        return
    print(f"{'VM':<20} {'PID':>7}  {'SSH':>7}  DIRECTORY")
    for inst in instances:
        ssh = str(inst["ssh_port"]) if inst["ssh_port"] is not None else "-"
        print(f"{inst['vm']:<20} {inst['pid']:>7}  {ssh:>7}  {inst['dir']}")


def _resolve_target(arg: str) -> dict:
    """Resolve a `view`/`stop` argument -- a PID or a VM NAME -- to the running-instance
    record ({vm, pid, dir, ssh_port}) it names, so those subcommands can act on a VM the
    user is NOT cd'd into. Enumerates the host (`_running_instances`) and matches:

      * an ALL-DIGIT arg is a PID: it must equal a running VM's pid exactly (a numeric
        arg is NEVER retried as a name -- a bogus pid is an error, not a name lookup).
      * otherwise it is a name: slugified the same way the VM's own dir basename is
        (so 'My Proj' matches the 'my-proj' VM), matched against each instance's vm.

    Dies with a clear, actionable message when nothing matches, or -- for a name that
    hits more than one VM (two dirs whose basenames slug alike) -- lists the candidate
    pids so the user can re-run against a specific one."""
    instances = _running_instances()
    if arg.isdigit():
        pid = int(arg)
        for inst in instances:
            if inst["pid"] == pid:
                return inst
        die(f"no running hypervisor VM with PID {pid} "
            "(list them with 'qvm ls')")
    name = _slugify(arg)
    matches = [inst for inst in instances if inst["vm"] == name]
    if not matches:
        die(f"no running hypervisor VM named '{name}' "
            "(list them with 'qvm ls')")
    if len(matches) > 1:
        pids = ", ".join(str(m["pid"]) for m in matches)
        die(f"more than one running VM named '{name}' (PIDs: {pids}) -- "
            "re-run against a specific PID")
    return matches[0]
