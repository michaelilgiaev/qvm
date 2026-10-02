"""command_line_interface.py - argument parsing, usage text, and the dispatch entry point.

This file parses args and calls into virtual_machine.py (the per-directory subcommands)
or configuration_defaults.py (the global `--configure` defaults surface); all the real
logic lives in the other modules.
"""

from __future__ import annotations

import os
import sys

# This is the CLI ENTRY the launcher execs. Flat sibling imports: the modules live directly
# in libraries/ (no package), so the bare imports resolve against this dir once it is on
# sys.path. The launcher runs this flat by absolute path and does NOT cd -- the caller's CWD
# is preserved so `Config.from_cwd()` resolves the VM against the directory the user is in.
# Mirrors packages/backup/backup.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configuration  # noqa: E402  (after the sys.path bootstrap above)
import configuration_defaults  # noqa: E402
import configuration_schema  # noqa: E402
import virtual_machine as vm  # noqa: E402
from checks import HypervisorError  # noqa: E402
from configuration import Config, DEFAULT_SSH_FORWARD_PORT  # noqa: E402


def usage(cfg: Config) -> str:
    return f"""\
qvm - run a QEMU/KVM VM from the current directory.

Each directory is its own independent VM (name derived from folder: '{cfg.vm}').
Files created here: azzio.qcow2 (disk), OVMF_VARS.4m.fd (UEFI NVRAM),
shared/ (host<->guest folder), hypervisor.cfg (settings).

USAGE:
  qvm install <file.iso> [--shared] [--ssh[=PORT]] [--clipboard] [--share-host-gpu]
                             Create disk + UEFI NVRAM + hypervisor.cfg (does NOT
                             boot). The ISO argument is REQUIRED. Flags set the
                             matching hypervisor.cfg toggles on. --ssh forwards
                             guest :22 to host Ssh_Forward_Port (49350 by default,
                             +1 per already-running VM; =PORT sets the base);
                             --clipboard shares the clipboard host<->guest.
  qvm run <file.qcow2> [--iso <file.iso>] [--headless]
                             Boot the named disk (REQUIRED). --iso attaches an
                             installer ISO for repair or first-time install. An
                             EMPTY disk auto-attaches the dir's single ISO.
                             --headless boots with NO viewer window (SPICE stays
                             up, so `qvm view` can attach later).
  qvm ls                     List every RUNNING qvm VM on this host
                             (name, pid, directory, SSH port).
  qvm view [PID|NAME]        Open a viewer window on a running VM (attach only --
                             closing it leaves the VM running). No argument targets
                             THIS dir's VM; a PID or VM name (from `ls`) targets any
                             running VM, so you need not be in its directory.
  qvm share [--offline]      Print commands to mount the host ./shared folder
                             inside the guest. --offline edits the powered-off
                             disk directly (Btrfs @/@home layout only).
  qvm status                 Show VM name, files, running state, SSH port, toggles.
  qvm stop [PID|NAME]        Power a VM off. No argument stops THIS dir's VM; a PID or
                             VM name (from `ls`) stops any running VM from anywhere.
  qvm --configure [--status | --set KEY VALUE | --reset]
                             Manage the GLOBAL defaults every NEW `qvm install`
                             starts from (this dir's own hypervisor.cfg still wins).
  qvm help                   This text.

hypervisor.cfg keys (all settings live here -- edit freely; True/False, strings quoted;
a running VM applies edits live where it can, and reverts a file with an invalid value):
  Share_Host_GPU                  guest uses the host GPU (shared, not passthrough);
                                  False = generic software-rendered GPU
  Network                         "user" (NAT) | "none" | a host interface to bridge
                                  (list interfaces: ip -br addr)
  Shared                          False | True (this dir) | an absolute host path
                                  to share into the guest via virtiofs
  Clipboard                       share the clipboard host<->guest (SPICE vdagent)
  Secure_Shell                    forward the guest's SSH port to the host
  Ports                           guest:host forwards, e.g. "22:49156, 1500:49157"
                                  (an explicit 22:host map pins the ssh forward)
  Ssh_Forward_Port                BASE host port the guest :22 forward starts from
                                  (49350 default; +1 per already-running VM)
  USB                             False | absolute device path(s) to pass through
                                  (find them: lsusb, lsblk -o NAME,TRAN,MOUNTPOINT)
  Fullscreen                      borderless exclusive fullscreen
  Ask_Before_Quitting_Hypervisor  prompt before closing the viewer window
  RAM                             MiB of guest RAM, or "N%" of host RAM (host: free -h)
  CPUs                            vCPU count, or "N%" of host CPUs (host: nproc)
  Disk_Size_GB                    qcow2 disk size in GiB, or "N%" of the host disk
  Audio                           True | False (True = PipeWire; confirm: pactl info)

ENV OVERRIDES (override hypervisor.cfg at runtime, not persisted):
  NETWORK  DISK_SIZE_GB  RAM  CPUS  AUDIO  PORTS  SHARED  USB
  SHARE_HOST_GPU=1  SECURE_SHELL=1  CLIPBOARD=1  FULLSCREEN=1  ASK_QUIT=1
  FORCE=1  YES=1  VENUS=1  DRYRUN=1   (legacy SSH=1 / SSHPORT / DISK_SIZE still honoured)

EXAMPLE:
  cd ~/Hypervisors/azzio
  qvm install azzio-2026.07.23-x86_64.iso --ssh --clipboard
  qvm run azzio.qcow2 --iso azzio-2026.07.23-x86_64.iso"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "help"
    rest = argv[1:]

    try:
        # `--configure` edits the GLOBAL user defaults (~/.config/azzio-hypervisor);
        # it is NOT a per-directory VM action, so it runs BEFORE Config.from_cwd() and
        # works from anywhere (an empty dir with no disk/iso would make from_cwd resolve
        # a VM that does not exist). Mirrors `azzio backup --configure`.
        if cmd in ("--configure", "-c", "configure"):
            return _do_configure(rest)

        cfg = Config.from_cwd()

        if cmd == "install":
            vm.do_install(cfg, *_parse_install_args(rest))
        elif cmd == "run":
            _dispatch_run(cfg, rest)
        elif cmd == "ls":
            vm.do_ls(cfg)
        elif cmd == "view":
            vm.do_view(cfg, rest[0] if rest else "")
        elif cmd == "share":
            vm.do_share(cfg, rest[0] if rest else "")
        elif cmd == "status":
            vm.do_status(cfg)
        elif cmd == "stop":
            vm.do_stop(cfg, rest[0] if rest else "")
        elif cmd in ("help", "-h", "--help"):
            print(usage(cfg))
        else:
            print(f"qvm: unknown subcommand: {cmd}\n", file=sys.stderr)
            print(usage(cfg), file=sys.stderr)
            return 2
    except HypervisorError as exc:
        print(f"qvm: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


def _configure_usage() -> str:
    keys = ", ".join(configuration_schema.KEYS)
    return (
        "Usage: qvm --configure --status\n"
        "       qvm --configure --set KEY VALUE\n"
        "       qvm --configure --reset\n\n"
        "Manage the GLOBAL defaults every NEW `qvm install` starts from\n"
        "(stored in " + configuration_defaults.defaults_path() + ").\n"
        "A directory's own hypervisor.cfg still wins for that VM.\n\n"
        "  --status         print the effective defaults (built-in + your overrides)\n"
        "  --set KEY VALUE  validate VALUE and save it as the default for KEY\n"
        "  --reset          delete all overrides (back to the built-in defaults)\n\n"
        "KEY is one of: " + keys
    )


def _do_configure(rest: list[str]) -> int:
    """The `qvm --configure` surface: manage the global default overrides. Returns an
    exit code. Non-interactive (the bare-`azzio` TUI drives --set/--status/--reset); mirrors
    `azzio backup --configure`. Never raises HypervisorError -- it validates via the schema
    and reports its own errors so a bad --set is a clean non-zero exit, not a traceback."""
    if not rest or rest[0] in ("-h", "--help", "help"):
        print(_configure_usage())
        return 0 if rest else 2

    opt = rest[0]
    if opt == "--status":
        sys.stdout.write(configuration.render_defaults_text(configuration.effective_defaults()))
        return 0
    if opt == "--reset":
        configuration_defaults.reset()
        print("qvm defaults reset to the built-in values.")
        return 0
    if opt == "--set":
        if len(rest) < 3:
            print("qvm --configure --set KEY VALUE: a KEY and VALUE are required.",
                  file=sys.stderr)
            return 2
        key, value = rest[1], rest[2]
        ok, err = configuration_defaults.set_key(key, value)
        if not ok:
            print(f"qvm --configure: {err}", file=sys.stderr)
            return 1
        print(f"qvm default set: {key} = {value.strip()}")
        return 0

    print(f"qvm --configure: unknown option: {opt}\n", file=sys.stderr)
    print(_configure_usage(), file=sys.stderr)
    return 2


def _parse_install_args(rest: list[str]) -> tuple:
    """Return (iso_arg, shared, ssh, share_host_gpu, ssh_port, clipboard) from install args.

    ssh_port is '' unless the user wrote --ssh=PORT or '--ssh PORT'; an empty
    string means "use the hypervisor.cfg default". (USB passthrough has no install
    flag -- it is a device-path list edited in hypervisor.cfg after install.)
    """
    iso_arg = ""
    shared = False
    ssh = False
    share_host_gpu = False
    ssh_port = ""
    clipboard = False
    i = 0
    while i < len(rest):
        token = rest[i]
        if token == "--shared":
            shared = True
        elif token == "--clipboard":
            clipboard = True
        elif token == "--share-host-gpu":
            share_host_gpu = True
        elif token == "--ssh":
            ssh = True
            # optional space-separated port: '--ssh 2222'
            if i + 1 < len(rest) and rest[i + 1].isdigit():
                ssh_port = rest[i + 1]
                i += 1
        elif token.startswith("--ssh="):
            ssh = True
            ssh_port = token.split("=", 1)[1]
        elif token.startswith("--"):
            print(f"qvm install: unknown flag: {token}", file=sys.stderr)
        elif not iso_arg:
            iso_arg = token
        i += 1
    return iso_arg, shared, ssh, share_host_gpu, ssh_port, clipboard


def _dispatch_run(cfg: Config, rest: list[str]) -> None:
    positional = [t for t in rest if not t.startswith("--")]
    disk_arg = positional[0] if positional else ""
    disk = cfg.resolve_run_disk(disk_arg)
    cfg = cfg.__class__(**{**cfg.__dict__, "disk": disk})

    # --headless: boot the VM with NO remote-viewer window (the unattended cache-build
    # path codelis drives). QEMU still creates the SPICE socket, so a later
    # `qvm view` can attach; we just never spawn our own viewer and block on
    # QEMU (+ virtiofsd) alone. Accepted with or without a value form for symmetry.
    headless = any(t == "--headless" or t.startswith("--headless=") for t in rest)

    iso_arg = _flag_value(rest, "--iso")
    if "--iso" in rest or iso_arg:
        iso = cfg.resolve_iso(iso_arg) if iso_arg else cfg.resolve_iso(os.environ.get("ISO", ""))
        vm.do_run(cfg, install_iso=iso, headless=headless)
    else:
        vm.do_run(cfg, headless=headless)


def _flag_value(rest: list[str], flag: str) -> str:
    """Value after `flag` (space-separated) or in `flag=value` form; '' if none."""
    for i, tok in enumerate(rest):
        if tok == flag and i + 1 < len(rest) and not rest[i + 1].startswith("--"):
            return rest[i + 1]
        if tok.startswith(flag + "="):
            return tok.split("=", 1)[1]
    return ""


# command_line_interface.py IS the CLI entry: main() lives here and the flat sibling imports
# at the top load it by absolute path (no package). The frozen `qvm` binary drives it through
# qvm_main.py (which imports main from here); this block also lets the file be run directly as
# a script.
if __name__ == "__main__":
    sys.exit(main())
