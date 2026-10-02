"""virtual_machine.py - the subcommand logic: install / run / share / status / stop.

Ported from libraries/install.sh, libraries/run.sh, libraries/share.sh and the
status/stop halves of hypervisor.sh. The QEMU command carries the smooth-1080p
config: virtio-vga-gl seeded with a 1920x1080 EDID mode, egl-headless GL offload
on the host GPU, SPICE with streaming-video/playback-compression off, and the
remote-viewer window opened full-screen. SPICE stays gl=off in every branch
(gl=on black-screens the NVIDIA driver at runtime; egl-headless does not).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time

# Flat sibling imports: the modules live directly in libraries/ (no package), so the
# bare imports resolve against this dir once it is on sys.path. The launcher execs the
# entry flat by absolute path and does NOT cd, so Config.from_cwd() still resolves the VM
# against the caller's directory. Mirrors packages/backup/archive.py's bootstrap.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402  (after the sys.path bootstrap above)
import configuration_watcher  # noqa: E402
from checks import die, is_running  # noqa: E402
from configuration import (  # noqa: E402
    Config, HypervisorCfg, _CFG_DEFAULTS, _hypervisor_cfg_text, select_ssh_port,
    GUEST_SSH_PORT, _migrate_legacy_keys,
)
from configuration_schema import coerce_all  # noqa: E402
from graphics import select_render_node  # noqa: E402
# build_qemu_argv + virtiofsd_argv are the pure argv builders (both in qemu_command);
# re-exported so do_run and the tests still reach vm.build_qemu_argv / vm.virtiofsd_argv.
from qemu_command import build_qemu_argv, virtiofsd_argv  # noqa: E402
# Host-wide `ls` enumeration lives in vm_instances (split for size + concern). Re-exported
# so vm.do_ls / vm._running_instances / vm._cfg_ssh_port / vm._pid_cwd still resolve here.
from vm_instances import (  # noqa: E402
    do_ls, _running_instances, _scan_proc_table, _pid_cwd, _cfg_ssh_port,
    _resolve_target,
)
# The `share` subcommand lives in vm_share (split for size). Re-exported so
# vm.do_share still resolves at its single call site in command_line_interface.
from vm_share import do_share, do_share_print, do_share_offline  # noqa: E402
# status/stop + the view/stop target resolver live in vm_lifecycle (split for size).
# Re-exported so vm.do_status / vm.do_stop resolve, and do_view finds _target_cfg.
from vm_lifecycle import (  # noqa: E402
    do_status, do_stop, _target_cfg, _target_cfg_and_pid, _pid_alive,
)



def _envflag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"


# --- virtiofs: the pure virtiofsd_argv builder lives in qemu_command.py ------
# It is a PURE argv builder (like build_qemu_argv), so it moved beside its sibling to
# hold this module under the size budget. Re-imported at the top of this module so
# vm.virtiofsd_argv still resolves for _spawn_virtiofsd and the tests that pin it.


# --- install -----------------------------------------------------------------
def do_install(cfg: Config, iso_arg: str,
               shared: bool = False,
               ssh: bool = False,
               share_host_gpu: bool = False,
               ssh_port: str = "",
               clipboard: bool = False) -> None:
    """Create disk + UEFI NVRAM + shared folder + hypervisor.cfg. Does not boot.
    Run 'qvm run <disk> --iso <iso>' to boot the installer afterward.
    The ISO argument is mandatory. (USB passthrough is not an install flag -- it
    is a list of device paths edited in hypervisor.cfg after install.)"""
    checks.require_writable_dir(cfg)
    checks.require_qemu()
    checks.require_ovmf(cfg)
    iso = cfg.resolve_iso(iso_arg)
    if not os.access(iso, os.R_OK):
        die(f"ISO not readable: {iso}")
    checks.require_free_space(cfg)

    # --- hypervisor.cfg: write all defaults + requested toggle overrides -----
    # vals holds COERCED values (bools/lists/Percent); the generator renders them.
    vals = dict(_CFG_DEFAULTS)
    vals["Shared"] = True if shared else False  # True == share the working dir
    vals["Secure_Shell"] = ssh
    vals["Clipboard"] = clipboard
    # share_host_gpu defaults ON; only a passed --share-host-gpu is redundant,
    # but honour the flag so it never turns the default off.
    if share_host_gpu:
        vals["Share_Host_GPU"] = True
    # --ssh turns Secure_Shell on and leaves the forward BASE at Ssh_Forward_Port (default
    # 49350); select_ssh_port bumps +1 per already-running VM, so N concurrent guests cascade
    # 49350, 49351, ... with no per-install pinning. --ssh=PORT (or --ssh PORT) instead sets
    # that base to PORT (still the floor the cascade climbs from). We write the base into the
    # Ssh_Forward_Port key, NOT a hard "22:PORT" map -- a hard map would peg every instance to
    # the same host port and defeat the manager. (An explicit "22:host" map a user hand-edits
    # into Ports still wins in select_ssh_port for the rare fixed-port case.)
    if ssh and ssh_port:
        vals["Ssh_Forward_Port"] = int(ssh_port)
    hcfg_path = HypervisorCfg.write(cfg.dir, vals)
    print(f"Config: {hcfg_path}")

    # --- disk: create only when missing; guard FORCE wipes -------------------
    if os.path.isfile(cfg.disk):
        if _envflag("FORCE"):
            used = _du_bytes(cfg.disk)
            if used > 1024 * 1024 * 1024 and not _envflag("YES"):
                die(
                    f"refusing FORCE wipe: {cfg.disk} holds ~{used // 1024 // 1024} MiB. "
                    "Re-run with FORCE=1 YES=1 to confirm."
                )
            _qemu_img_create(cfg)
            print(f"Recreated {cfg.disk_size} disk (wiped): {cfg.disk}")
        else:
            print(f"Disk exists, keeping it: {cfg.disk}  (FORCE=1 to wipe)")
    else:
        _qemu_img_create(cfg)
        print(f"Created {cfg.disk_size} disk: {cfg.disk}")

    # --- UEFI NVRAM: copy only when missing ----------------------------------
    if os.path.isfile(cfg.vars):
        print(f"UEFI NVRAM kept: {cfg.vars}")
    else:
        shutil.copyfile(cfg.vars_tmpl, cfg.vars)
        print(f"UEFI NVRAM ready: {cfg.vars}")

    # --- shared folder (only when enabled) -----------------------------------
    if shared:
        os.makedirs(cfg.shared, exist_ok=True)
        os.chmod(cfg.shared, 0o755)
        print(f"Shared folder ready: {cfg.shared}")

    print()
    print(f"Ready. Boot the installer with:  "
          f"qvm run {os.path.basename(cfg.disk)} --iso {os.path.basename(iso)}")


def _qemu_img_create(cfg: Config) -> None:
    try:
        os.remove(cfg.disk)
    except FileNotFoundError:
        pass
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", cfg.disk, cfg.disk_size],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def _du_bytes(path: str) -> int:
    """Real bytes allocated on disk (like `du -B1`), for the FORCE-wipe guard."""
    try:
        return os.stat(path).st_blocks * 512
    except OSError:
        return 0


_EMPTY_DISK_FLOOR = 1024 * 1024  # < 1 MiB allocated == never installed


def _auto_install_iso(cfg: Config, requested: str, disk: str) -> str:
    """Decide which installer ISO to attach as a CD-ROM (or '').

    PURE. An explicit request (--iso / INSTALL_ISO=) always wins and is returned
    verbatim -- used to repair or reinstall an already-populated disk. With no
    request, an EMPTY (never-installed) disk falls back to the directory's single
    *.iso via cfg.find_iso(); a NON-empty disk, or zero-or-many ISOs, returns ''
    so a normal boot never surprise-attaches media.
    """
    if requested:
        return requested
    if _du_bytes(disk) >= _EMPTY_DISK_FLOOR:
        return ""
    return cfg.find_iso()


# --- run ---------------------------------------------------------------------
def do_run(cfg: Config, install_iso: str = "", headless: bool = False) -> None:
    """Assemble and launch the QEMU VM, then a remote-viewer window against it.
    Closing that window (or Ctrl-C) tears the whole VM down. cfg.disk is the
    already-resolved .qcow2 the caller demanded on the command line.

    headless=True boots the VM with NO viewer window: QEMU (and virtiofsd) still
    run and QEMU still creates the SPICE socket -- so a `qvm view` can
    attach later -- but we never spawn remote-viewer and we block on QEMU (+
    virtiofsd) alone. This is the unattended path codelis uses to run the ISO's
    auto-install without a display; remote-viewer is not even required then."""
    checks.require_writable_dir(cfg)
    checks.require_qemu()
    checks.require_ovmf(cfg)
    checks.require_kvm()
    if not headless:
        checks.require_viewer()
    checks.require_not_running(cfg)

    hcfg = cfg.hcfg
    disk = cfg.disk
    if not os.path.isfile(cfg.vars):
        shutil.copyfile(cfg.vars_tmpl, cfg.vars)
    # Only auto-create the DEFAULT working ./shared dir; a user-named custom path
    # is the user's own responsibility (we never mkdir an arbitrary host path).
    if hcfg.shared is True:
        os.makedirs(cfg.shared, exist_ok=True)
        os.chmod(cfg.shared, 0o755)
    # The shared folder rides virtiofs -> we need the virtiofsd daemon. Gate it here
    # (only when shared is on) so a plain non-shared VM never demands it.
    if cfg.shared_path:
        checks.require_virtiofsd()

    # --- GPU: shared host GPU (3D) vs a generic software-rendered GPU --------
    gpu_args = _gpu_args(cfg)

    # --- installer ISO as a SATA CD-ROM (repair / first-time install) --------
    # Explicit --iso (or INSTALL_ISO=) wins; otherwise an EMPTY (never-installed)
    # disk with exactly one *.iso in the dir auto-attaches it, so a fresh `run`
    # boots the installer instead of hanging at the UEFI shell.
    requested = install_iso or os.environ.get("INSTALL_ISO", "")
    iso = _auto_install_iso(cfg, requested, disk)
    iso_args: list[str] = []
    if iso and os.path.isfile(iso):
        iso_args = [
            "-device", "ich9-ahci,id=sata",
            "-drive", f"if=none,id=cd0,file={iso},media=cdrom,readonly=on",
            "-device", "ide-cd,drive=cd0,bus=sata.0,bootindex=2",
        ]
        if requested:
            print(f"Installer ISO attached: {os.path.basename(iso)}", file=sys.stderr)
        else:
            print(f"Disk is empty -- auto-attaching ISO: {os.path.basename(iso)}",
                  file=sys.stderr)
    elif iso:
        # a requested ISO (INSTALL_ISO=) that does not exist: warn, don't silently
        # boot with no media. (The CLI --iso path already dies via resolve_iso.)
        print(f"WARNING: requested ISO not found, booting without it: {iso}",
              file=sys.stderr)

    port = select_ssh_port(cfg) if hcfg.secure_shell else None
    port_maps = _resolve_port_maps(cfg, port)
    _write_viewer_ask_quit(hcfg.ask_before_quitting_hypervisor)

    checks.require_not_running(cfg)
    _rm(cfg.spice_sock)

    qemu = build_qemu_argv(cfg, disk=disk, gpu_args=gpu_args, iso_args=iso_args,
                           port_maps=port_maps)

    if _envflag("DRYRUN"):
        print(" ".join(_shquote(a) for a in qemu))
        return

    _launch(cfg, qemu, port, headless=headless)


def _resolve_port_maps(cfg: Config, ssh_port: "int | None") -> list:
    """The (guest, host) forwards QEMU should install for this boot.

    Starts from the cfg's Ports maps, but the guest-:22 map's HOST port is replaced by
    `ssh_port` -- the bump-aware port select_ssh_port picked (which may differ from the
    cfg value when the configured port was busy). When Secure_Shell is on but the cfg
    pinned no explicit 22 map, the resolved ssh forward is still added so `qvm ssh`
    has a port. When Secure_Shell is off, any 22 map is dropped (no ssh forward)."""
    maps = [(g, h) for (g, h) in cfg.hcfg.ports if g != GUEST_SSH_PORT]
    if ssh_port is not None:
        maps.insert(0, (GUEST_SSH_PORT, ssh_port))
    return maps


def _gpu_args(cfg: Config) -> list[str]:
    """Display/GPU argv. share_host_gpu=on offloads guest GL onto a host DRM
    render node (shared, NOT passthrough -- the host screen keeps working);
    off (or no usable node) gives a generic 2D virtio-vga."""
    if not cfg.share_host_gpu:
        print("share_host_gpu=false -- generic GPU (software rendering)", file=sys.stderr)
        return ["-device", "virtio-vga", "-display", "none"]

    rendernode = select_render_node()
    if not (rendernode and os.path.exists(rendernode)):
        print("share_host_gpu=true but no usable host render node -- "
              "falling back to a generic GPU", file=sys.stderr)
        return ["-device", "virtio-vga", "-display", "none"]

    # xres/yres seed the virtio-gpu EDID with a 1920x1080 preferred mode so the
    # guest comes up at full-HD geometry early (UEFI/console). The authoritative
    # resolution for the running desktop comes from the guest spice-vdagent.
    vga = "virtio-vga-gl,xres=1920,yres=1080"
    if _envflag("VENUS"):
        hostmem = os.environ.get("VENUS_HOSTMEM", "8G")
        vga += f",blob=on,venus=on,hostmem={hostmem}"
        print(f"Vulkan (Venus) enabled: blob=on,venus=on,hostmem={hostmem}",
              file=sys.stderr)
    print(f"Sharing host GPU (3D offload): {rendernode}", file=sys.stderr)
    return ["-device", vga, "-display", f"egl-headless,rendernode={rendernode}"]


def _make_snapshot(cfg: Config) -> "configuration_watcher.Snapshot":
    """The last-known-good snapshot the watcher reverts to: the CURRENT on-disk
    hypervisor.cfg text (so a revert restores the user's exact file, comments and
    all) with the already-validated coerced values from cfg.hcfg.

    Falls back to a freshly-rendered body if the file is unreadable OR keyless
    (empty / all-comments). A keyless baseline must never be adopted: reverting
    to it would restore an empty file (or be refused), bricking the next boot --
    the exact failure this feature exists to prevent.

    The snapshot VALUES are the coerced-but-UNRESOLVED map (canonical keys, RAM/CPUs/
    Disk_Size_GB kept as their Percent spec where the file uses one) -- the SAME shape
    evaluate_save produces from a re-save -- so an identical save is correctly seen as a
    no-op instead of a spurious change (cfg.hcfg holds resolved ints, which would not
    match a "15%" re-coerce)."""
    try:
        with open(cfg.hypervisor_cfg_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""
    if not configuration_watcher._has_known_keys(text):
        # No usable file: render a canonical default body and take its values as baseline.
        base = dict(_CFG_DEFAULTS)
        text = _hypervisor_cfg_text(base)
        values = base
    else:
        coerced, _errors = coerce_all(_migrate_legacy_keys(
            configuration_watcher._parse_text(text)))
        # Layer over the defaults so keys the file omits still have a baseline value.
        values = dict(_CFG_DEFAULTS)
        values.update(coerced)
    return configuration_watcher.Snapshot(values=values, text=text)


def _tty_save() -> "tuple[int, list] | None":
    """Snapshot the controlling terminal's attributes so teardown can restore them.
    Returns (fd, saved_attrs) or None when stdin is not a tty (piped/headless runs
    have no terminal to corrupt or restore). Best-effort: any termios failure -> None."""
    try:
        if not sys.stdin.isatty():
            return None
        import termios
        fd = sys.stdin.fileno()
        return fd, termios.tcgetattr(fd)
    except (OSError, ValueError, ImportError):
        return None


def _tty_restore(saved: "tuple[int, list] | None") -> None:
    """Put the controlling terminal back the way we found it. This is the fix for the
    corrupted-tab bug: remote-viewer links libvte, which puts the shared controlling
    tty into raw/no-echo mode; when it is killed on teardown (SIGKILL from cleanup, or
    the terminal's own SIGINT on Ctrl-C) VTE never restores it, so the shell is left in
    -echo/-icanon -- typing shows nothing and the prompt renders mangled. We restore the
    snapshot on EVERY exit path (called from cleanup, which all paths funnel through).
    Belt-and-braces `stty sane` re-cooks anything the snapshot did not cover (alt-screen,
    bracketed paste). No-op when there was no tty to save."""
    if saved is None:
        return
    fd, attrs = saved
    try:
        import termios
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except Exception:  # never let terminal restore raise on a teardown path
        pass
    # `stty sane` re-cooks anything the snapshot did not cover (alt-screen, bracketed
    # paste). Point it at the SAVED terminal fd (not sys.stdin, which may be a pseudo-file
    # with no fileno on some stdins); best-effort and never allowed to raise on teardown.
    try:
        subprocess.run(["stty", "sane"], stdin=fd,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _spawn_viewer(cfg: Config) -> "subprocess.Popen":
    """Spawn remote-viewer against the VM's SPICE socket and return the process.

    Shared by _launch (the windowed boot) and do_view (attach to an already-running
    VM), so the viewer arg-building, DISPLAY override and the stdin=DEVNULL tty fix
    live in ONE place. Default is a maximized, WM-decorated window with a known
    title; hcfg.fullscreen opts into borderless exclusive fullscreen instead.
    --auto-resize=always keeps the guest following the window size (needs guest
    spice-vdagent). HYPERVISOR_VIEWER_DISPLAY pins which X display the viewer maps on.

    stdin=DEVNULL is the source-side half of the tty fix: remote-viewer links libvte,
    which -- given a controlling tty on stdin -- puts it into raw mode and (when killed
    on teardown) leaves it -echo/-icanon, mangling the shell. Handing it /dev/null means
    it has no terminal to corrupt; _tty_restore in cleanup is the belt-and-braces second
    half for anything that still slips through."""
    hcfg = cfg.hcfg
    title = f"qvm: {cfg.vm}"
    if hcfg.fullscreen:
        view_args = ["--full-screen", "--auto-resize=always"]
    else:
        view_args = ["--auto-resize=always", "--title", title]
    viewer_env = os.environ.copy()
    viewer_display = os.environ.get("HYPERVISOR_VIEWER_DISPLAY")
    if viewer_display:
        viewer_env["DISPLAY"] = viewer_display
    if not hcfg.fullscreen:
        _maximize_window(title, display=viewer_display)
    return subprocess.Popen(
        ["remote-viewer", *view_args, f"spice+unix://{cfg.spice_sock}"],
        env=viewer_env,
        stdin=subprocess.DEVNULL,
    )


def _launch(cfg: Config, qemu: list[str], port: "int | None",
            headless: bool = False) -> None:
    hcfg = cfg.hcfg
    """Boot QEMU, wait for the SPICE socket, launch the viewer; whichever dies
    first tears the other down. Mirrors run.sh's trap-based lifecycle. A
    ConfigWatcher runs alongside, applying live hypervisor.cfg edits and reverting
    invalid ones.

    headless=True skips the viewer entirely (no remote-viewer, no window maximize)
    and blocks on QEMU (+ virtiofsd) alone -- QEMU still creates the SPICE socket so
    `qvm view` can attach later. cleanup() is unchanged: viewer_proc stays None,
    which the kill loop and _wait_any both tolerate."""
    qemu_proc: subprocess.Popen | None = None
    viewer_proc: subprocess.Popen | None = None
    virtiofsd_proc: subprocess.Popen | None = None
    watcher: "configuration_watcher.ConfigWatcher | None" = None
    # Snapshot the terminal BEFORE spawning any child, so teardown can undo a child
    # (remote-viewer/VTE) leaving it raw. See _tty_restore.
    saved_tty = _tty_save()

    _cleaned = {"done": False}

    def cleanup(*_a) -> None:
        # Idempotent: cleanup runs from the signal handler AND the finally block, so a
        # Ctrl-C that fires mid-teardown must not double-kill or double-restore the tty.
        if _cleaned["done"]:
            return
        _cleaned["done"] = True
        if watcher is not None:
            watcher.stop()
        # Kill every child we spawned so NOTHING outlives the VM -- viewer, QEMU, and
        # the virtiofsd daemon (now a plain non-root child of ours, so kill() reaches
        # it directly; no sudo, no orphaned root daemon holding the share dir open).
        for p in (viewer_proc, qemu_proc, virtiofsd_proc):
            if p and p.poll() is None:
                try:
                    p.kill()
                except OSError:
                    pass
        # Belt-and-braces: reap any stray process by name/socket in case a child got
        # reparented (e.g. this python was itself killed and re-run). Rootless now, so
        # a plain pkill (no sudo) can touch them -- the whole point is that nuking the
        # venv never leaves a zombie you have to hunt down in htop.
        subprocess.run(["pkill", "-9", "-x", cfg.proc],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", f"virtiofsd.*{cfg.virtiofs_sock}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _rm(cfg.spice_sock)
        _rm_sock(cfg.virtiofs_sock)
        _rm(cfg.virtiofs_pidfile)
        # LAST: undo any terminal corruption a child (remote-viewer/VTE) left behind.
        # Runs on every teardown path because they all funnel through cleanup().
        _tty_restore(saved_tty)

    # Ctrl-C / TERM -> cleanup then exit, matching the bash trap.
    def _sig(_signum, _frame):
        cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    ssh_info = f"  SSH -> localhost:{port}" if port is not None else ""
    print(
        f"Booting VM '{cfg.vm}': {cfg.cpus} vCPU, {cfg.ram} MiB RAM.{ssh_info}",
        file=sys.stderr,
    )

    try:
        # Spawn the virtiofsd daemon FIRST (when shared is on): QEMU's vhost-user
        # chardev connects to its socket at startup, so the socket must already be
        # listening. Depends only on shared -- never on ssh -- so the share appears
        # on every variant. Killed in cleanup() with the rest of the VM.
        virtiofsd_proc = _spawn_virtiofsd(cfg)

        qemu_proc = subprocess.Popen(qemu)

        # wait for the SPICE socket, then launch our own viewer against it (unless
        # headless -- QEMU still CREATES the socket either way, so `qvm view`
        # can attach to a headless VM later; we just do not open a window here).
        for _ in range(100):
            if os.path.exists(cfg.spice_sock):
                break
            if qemu_proc.poll() is not None:
                die("QEMU exited before the SPICE socket appeared (see errors above)")
            time.sleep(0.1)

        # A normal, MAXIMIZED (or fullscreen) window, built by the shared _spawn_viewer
        # helper. Skipped entirely when headless: no window, no _maximize_window, and
        # viewer_proc stays None (the cleanup kill loop and _wait_any both tolerate that).
        if not headless:
            viewer_proc = _spawn_viewer(cfg)

        # Watch hypervisor.cfg for live edits: valid ones are applied/logged,
        # invalid ones are reverted to the file we booted with.
        watcher = configuration_watcher.ConfigWatcher(cfg.hypervisor_cfg_path,
                                               _make_snapshot(cfg))
        watcher.start()

        # Whichever of the coupled processes dies first drops us into cleanup, which
        # kills the rest -- so the three live and die together:
        #   * close the viewer window  -> viewer exits  -> QEMU + daemon killed
        #   * guest powers off / QEMU crashes -> QEMU exits -> viewer + daemon killed
        #   * virtiofsd dies (broken share) -> tear the VM down rather than run on
        #     with a half-dead mount
        _wait_any(qemu_proc, viewer_proc, virtiofsd_proc)
    finally:
        cleanup()


def _wait_any(*procs: "subprocess.Popen | None") -> None:
    """Block until ANY of the given processes exits (bash `wait -n`). None entries
    (e.g. no virtiofsd when the share is off) are ignored. Polled at a tight 50ms so
    the survivor is torn down effectively instantly -- the viewer must not linger on a
    dead VM, nor QEMU on a closed window."""
    watched = [p for p in procs if p is not None]
    while True:
        if any(p.poll() is not None for p in watched):
            return
        time.sleep(0.05)


def _spawn_virtiofsd(cfg: Config) -> "subprocess.Popen | None":
    """Start the virtiofsd daemon that backs the shared folder, or None when shared
    is off. Removes any stale socket, launches the daemon ROOTLESS (argv from the pure
    virtiofsd_argv -- see there for why no sudo), then waits for the socket to appear
    so QEMU's vhost-user chardev can connect. Dies if the daemon exits before the
    socket shows up.

    The daemon runs as the invoking user, so the socket it creates is already owned by
    us and QEMU (same user) opens it directly -- no group hand-off, no chmod."""
    argv = virtiofsd_argv(cfg)
    if not argv:
        return None
    _rm_sock(cfg.virtiofs_sock)
    print(f"Starting virtiofsd for shared folder: {cfg.shared_path}",
          file=sys.stderr)
    proc = subprocess.Popen(argv)
    # Record the daemon's pid beside its socket (virtiofs.sock.pid). It is a runtime
    # artifact -- created here, removed in cleanup() with the socket -- so a warm VM dir
    # carries it (the codelis cache layout lists it) and any external watcher can find
    # the daemon without re-scanning the process table. Best-effort: a dir we cannot write
    # to must not abort the boot.
    _write_pidfile(cfg.virtiofs_pidfile, proc.pid)
    for _ in range(100):  # up to ~10s for the socket to appear
        if os.path.exists(cfg.virtiofs_sock):
            return proc
        if proc.poll() is not None:
            die("virtiofsd exited before its socket appeared -- shared folder "
                "cannot be mounted (see errors above)")
        time.sleep(0.1)
    return proc


def _write_pidfile(path: str, pid: int) -> None:
    """Write `pid` to `path` (the virtiofsd pid file). Best-effort -- an unwritable
    dir simply leaves no pid file rather than failing the VM boot."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{pid}\n")
    except OSError:
        pass


def _rm_sock(path: str) -> None:
    """Remove a leftover vhost-user socket. Now that virtiofsd runs rootless the
    socket is owned by the invoking user, so a plain unlink always succeeds. Best-
    effort -- a stale socket only matters if it still exists when virtiofsd tries to
    bind."""
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError:
        pass


def _maximize_window(title: str, display: "str | None" = None) -> None:
    """Maximize the remote-viewer window once it maps, in a background thread."""
    if shutil.which("wmctrl") is None:
        return

    env = os.environ.copy()
    if display:
        env["DISPLAY"] = display

    def worker() -> None:
        for _ in range(100):  # up to ~20s for the window to map
            time.sleep(0.2)
            try:
                out = subprocess.run(
                    ["wmctrl", "-l"], capture_output=True, text=True, env=env
                ).stdout
            except FileNotFoundError:
                return
            win_id = None
            for line in out.splitlines():
                parts = line.split(None, 3)
                if len(parts) == 4 and title in parts[3]:
                    win_id = parts[0]
                    break
            if win_id:
                subprocess.run(
                    ["wmctrl", "-i", "-r", win_id, "-b",
                     "add,maximized_vert,maximized_horz"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=env,
                )
                return

    import threading

    threading.Thread(target=worker, daemon=True).start()


def _write_viewer_ask_quit(ask_quit: bool) -> None:
    """Set ask-quit=false so remote-viewer doesn't nag on window close, unless
    ask_quit=true in hypervisor.cfg."""
    if ask_quit:
        return
    vv = os.path.expanduser("~/.config/virt-viewer/settings")
    os.makedirs(os.path.dirname(vv), exist_ok=True)
    existing = ""
    if os.path.isfile(vv):
        with open(vv, encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
    if "ask-quit=false" in existing:
        return
    if "[virt-viewer]" in existing:
        new = existing.replace("[virt-viewer]", "[virt-viewer]\nask-quit=false", 1)
    else:
        new = existing + "[virt-viewer]\nask-quit=false\n"
    with open(vv, "w", encoding="utf-8") as fh:
        fh.write(new)


# --- share (lives in vm_share.py) --------------------------------------------
# The share flow -- the guest-side instruction text, the offline qemu-nbd/btrfs disk
# edit, and the sudo/block-device helpers it alone uses -- was split into vm_share.py to
# hold this module under the size budget. do_share is re-imported at the top of this
# module so vm.do_share still resolves at its single call site in command_line_interface.


# --- status / stop (live in vm_lifecycle.py) ---------------------------------
# do_status, do_stop, and the _target_cfg / _target_cfg_and_pid / _pid_alive helpers
# were split into vm_lifecycle.py to hold this module under the size budget. They are
# re-imported at the top of this module so vm.do_status / vm.do_stop still resolve at
# their call sites in command_line_interface, and do_view below still finds _target_cfg.


# --- ls: every running VM on the host ----------------------------------------
# The enumeration backend (_scan_proc_table, _pid_cwd, _cfg_ssh_port,
# _running_instances, do_ls) lives in vm_instances.py -- host-wide discovery is a
# separate concern from this module's single-VM lifecycle, and splitting it holds this
# file's size down. They are re-imported at the top of this module so vm.do_ls and the
# vm._running_instances / vm._cfg_ssh_port / vm._pid_cwd names still resolve here.


# --- view: attach a viewer to THIS dir's running VM --------------------------
def do_view(cfg: Config, arg: str = "") -> None:
    """Open a remote-viewer (virt-viewer) window on an already-running VM and BLOCK on
    it. With no argument it targets THIS directory's VM; with a PID or a VM name it
    targets whichever running instance that resolves to, so you can view a VM you are
    not cd'd into. Attach-only: closing the window leaves the VM running (unlike `run`,
    whose viewer close tears the VM down). Refuses when remote-viewer is missing, the VM
    is not running, or its SPICE socket is absent."""
    checks.require_viewer()
    cfg = _target_cfg(cfg, arg)
    if not is_running(cfg):
        die(f"VM '{cfg.vm}' is not running -- start it with 'qvm run' first.")
    if not os.path.exists(cfg.spice_sock):
        die(f"no SPICE socket for VM '{cfg.vm}' at {cfg.spice_sock} -- "
            "is it running headless without a socket yet?")
    print(f"Attaching viewer to VM '{cfg.vm}' (closing the window leaves it running).",
          file=sys.stderr)
    viewer_proc = _spawn_viewer(cfg)
    try:
        viewer_proc.wait()
    except KeyboardInterrupt:
        # Ctrl-C detaches the viewer only; the VM keeps running (attach semantics).
        if viewer_proc.poll() is None:
            try:
                viewer_proc.kill()
            except OSError:
                pass


# --- small shell/OS helpers --------------------------------------------------
def _rm(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _shquote(s: str) -> str:
    import shlex
    return shlex.quote(s)
