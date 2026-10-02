"""qemu_command.py - the pure QEMU command-line assembler.

build_qemu_argv() takes already-resolved inputs (the system disk path, the
display/gpu args, the installer-ISO args, and the forwarded SSH port) and returns
the full argv list. It is PURE: no process launch, no filesystem mutation. That
purity is what lets the command be pinned in tests without a real host.

virtual_machine.do_run decides the host-dependent inputs (render node, whether an
ISO is attached) and keeps the checks + launch; this module just assembles. The
audio, shared-folder (virtiofs), networking, and USB blocks are gated on the
config here so the whole command lives in one place.

Extracted from virtual_machine.py to keep that module under the 750-line limit
once the richer usb/shared/network handling landed.
"""

from __future__ import annotations

import os
import sys

# Flat sibling imports: the modules live directly in libraries/ (no package).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402  (after the sys.path bootstrap above)
from configuration import Config  # noqa: E402


def _audio_args(cfg: Config) -> list[str]:
    """PipeWire duplex audio when Audio is True; nothing when False."""
    if not cfg.audio:
        return []
    return [
        "-audiodev", "pipewire,id=snd0",
        "-device", "ich9-intel-hda,id=hda",
        "-device", "hda-duplex,bus=hda.0,audiodev=snd0",
    ]


def _clipboard_args(cfg: Config) -> list[str]:
    """The SPICE vdagent channel that carries host<->guest clipboard sharing (and guest
    display resize), gated on the Clipboard toggle. It rides the always-present
    virtio-serial bus as a spicevmc chardev exposed on the well-known
    com.redhat.spice.0 port the guest's spice-vdagent connects to. Off -> no channel,
    so nothing is shared. The -spice display itself is added unconditionally in
    build_qemu_argv (the viewer needs it); only the CLIPBOARD channel is optional."""
    if not cfg.hcfg.clipboard:
        return []
    return [
        "-chardev", "spicevmc,id=vdagent,name=vdagent",
        "-device", "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
    ]


def _shared_args(cfg: Config) -> list[str]:
    """virtiofs export of the host share dir, or nothing when shared is off.

    The QEMU side is just the vhost-user FRONTEND: a chardev pointing at the
    virtiofsd daemon's UNIX socket, and a vhost-user-fs device advertising the
    stable mount tag "shared" (the guest fstab source). The host directory itself
    is NOT named here -- virtiofsd (spawned by virtual_machine._spawn_virtiofsd)
    exports it; QEMU only sees the socket. The required shared memory-backend is
    added separately in build_qemu_argv (it replaces the plain -m allocation).

    cfg.shared_path resolves the union type: True -> the working ./shared dir, a
    string -> that host path, False -> '' (disabled)."""
    if not cfg.shared_path:
        return []
    return [
        "-chardev", f"socket,id=virtiofs0,path={cfg.virtiofs_sock}",
        "-device", "vhost-user-fs-pci,queue-size=1024,chardev=virtiofs0,tag=shared",
    ]


def _memory_args(cfg: Config) -> list[str]:
    """RAM wiring. Normally a plain '-m <ram>'. But virtiofs (vhost-user) needs the
    guest RAM to live in a SHARED memory-backend the daemon can map, so when shared
    is on we swap the plain allocation for a memory-backend-memfd (share=on) hung on
    a single NUMA node. The memfd size must EXACTLY equal -m (one node covering all
    guest RAM; QEMU rejects the boot if the node total != -m), so both use the same
    cfg.ram value. With shared OFF this is exactly '-m <ram>', byte-identical to
    before -- non-shared VMs are untouched."""
    if not cfg.shared_path:
        return ["-m", cfg.ram]
    return [
        "-m", cfg.ram,
        "-object", f"memory-backend-memfd,id=mem,size={cfg.ram}M,share=on",
        "-numa", "node,memdev=mem",
    ]


def _net_args(cfg: Config, port_maps: "list | None") -> list[str]:
    """Guest networking from cfg.network:
      * user       -> QEMU user-mode NAT (+ a hostfwd per configured guest:host map).
      * none       -> no NIC at all.
      * <iface>    -> bridge a virtio NIC onto that host interface (needs the
                      iface to be a bridge / qemu-bridge-helper; wifi usually
                      cannot be bridged).

    port_maps is the RESOLVED list of (guest, host) forwards (the ssh 22:host map's host
    is the bump-aware port do_run picked). Each becomes hostfwd=tcp::<host>-:<guest>.
    hostfwd only applies to user-mode NAT; a bridge ignores it.
    """
    net = cfg.hcfg.network
    if net == "none":
        return []
    if net == "user":
        netdev = "user,id=net0"
        for guest, host in (port_maps or []):
            netdev += f",hostfwd=tcp::{host}-:{guest}"
        return ["-netdev", netdev, "-device", "virtio-net-pci,netdev=net0"]
    # a named host interface -> bridged. hostfwd does not apply to a bridge.
    return ["-netdev", f"bridge,id=net0,br={net}",
            "-device", "virtio-net-pci,netdev=net0"]


def _usb_args(cfg: Config) -> list[str]:
    """Pass each configured USB device through to the guest via usb-host.

    cfg.usb is a list of absolute host device paths (e.g. /dev/bus/usb/003/004).
    Empty list -> no controller, no devices. One xHCI controller carries all of
    them."""
    devices = cfg.hcfg.usb
    if not devices:
        return []
    args = ["-device", "qemu-xhci,id=xhci"]
    for i, path in enumerate(devices):
        args += ["-device",
                 f"usb-host,hostdevice={path},id=usbhost{i},bus=xhci.0"]
    return args


def build_qemu_argv(cfg: Config, *, disk: str, gpu_args: list[str],
                    iso_args: list[str], port_maps: "list | None" = None) -> list[str]:
    """Assemble the full QEMU command line as an argv list. PURE.

    port_maps is the resolved list of (guest, host) forwards for user-mode networking
    (see _net_args); None/[] means no forwards. The clipboard channel is added only when
    the Clipboard toggle is on (see _clipboard_args)."""
    return [
        "qemu-system-x86_64",
        "-name", f"{cfg.vm},process={cfg.proc}",
        "-nodefaults",
        "-machine", "q35,accel=kvm,vmport=off",
        "-cpu", "host",
        "-smp", f"{cfg.cpus},sockets=1,cores={cfg.cpus},threads=1",
        *_memory_args(cfg),
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={cfg.code}",
        "-drive", f"if=pflash,format=raw,unit=1,file={cfg.vars}",
        "-drive", f"if=none,id=disk0,file={disk},format=qcow2,cache=writeback,discard=unmap,aio=threads",
        "-device", "virtio-blk-pci,drive=disk0,bootindex=1",
        *iso_args,
        *gpu_args,
        "-spice", f"unix=on,addr={cfg.spice_sock},disable-ticketing=on,gl=off,streaming-video=off,playback-compression=off",
        "-device", "virtio-serial-pci",
        *_clipboard_args(cfg),
        *_shared_args(cfg),
        *_net_args(cfg, port_maps),
        "-device", "virtio-keyboard-pci",
        "-device", "virtio-tablet-pci",
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0",
        *_usb_args(cfg),
        *_audio_args(cfg),
        "-rtc", "base=utc,driftfix=slew",
        "-global", "kvm-pit.lost_tick_policy=discard",
    ]


# --- virtiofs shared folder --------------------------------------------------
def virtiofsd_argv(cfg: Config) -> list[str]:
    """The virtiofsd daemon command that exports the host share dir on the VM's
    vhost-user socket, or [] when shared is off. PURE (no spawn) so it can be pinned
    in tests. Depends ONLY on cfg.shared_path -- NOT on ssh -- so the share works on
    every variant: the daemon runs whenever shared is set, not as a side effect of
    the ssh bring-up.

    Runs ROOTLESS -- NO sudo. sudo is unreliable on this host (a bugged sudo just
    failed to start the daemon, so the socket never appeared and QEMU died with
    "Failed to connect ... No such file or directory"). Rootless virtiofsd needs no
    privilege: it runs as the invoking user, the socket it creates is owned by that
    same user, and the (also non-root) QEMU opens it directly -- no --socket-group,
    no chmod dance. The tradeoff of dropping root is that the daemon can no longer
    setfsuid() to arbitrary guest credentials: a create/write stamped with a guest
    id the host user does NOT hold is rejected by the host kernel with EPERM
    ("Operation not permitted"), even on an rw mount owned by the guest user. This
    bites whenever the guest's uid/gid differ from the host's -- e.g. an azzio guest
    on uid 1000 but PRIMARY gid 998 (autologin), whose every write carries gid 998,
    a gid the host user (gid 1000) cannot act as. The result is a share that mounts
    rw yet denies all writes.

    --translate-uid / --translate-gid in 'squash-guest' mode fix this: they collapse
    the ENTIRE guest id range down to the single host id, so no matter what uid/gid
    the guest stamps (998, 1000, anything), virtiofsd performs the operation on the
    host as our own uid/gid -- which we own -- and the write always succeeds. Files
    the guest creates come back owned by the guest user (the guest sees its own ids;
    only the host-side action is squashed). 'squash-guest:0:<host-id>:<count>' maps
    guest ids [0, count) to <host-id>; a full-range count covers every possible id.
    (Cannot combine with --posix-acl=always|auto, which we do not enable.)

    --sandbox=none keeps the daemon in the host mount namespace (the default sandbox
    would pivot_root INTO the shared dir); the socket is one per VM dir so two VMs
    never collide."""
    path = cfg.shared_path
    if not path:
        return []
    # Resolve the binary, but fall back to the bare name so this stays a PURE,
    # host-independent builder: on a machine without virtiofsd installed (a CI
    # runner, say) checks.virtiofsd_binary() returns '' and would otherwise emit
    # an empty argv slot. The bare "virtiofsd" keeps the command well-formed for
    # pinning; whether the daemon is actually present is enforced separately by
    # require_virtiofsd() before any real spawn.
    binary = checks.virtiofsd_binary() or "virtiofsd"
    # Squash every guest uid/gid onto OUR real host uid/gid so any guest write lands
    # as an id we own and never hits EPERM (see docstring). getuid/getgid, not a
    # hardcoded 1000, so this is correct whatever user actually launches the daemon.
    # 0xffffffff (2^32-1) as the range count covers the whole 32-bit id space, so no
    # guest id -- the autologin gid 998 included -- ever escapes the squash.
    host_uid, host_gid = os.getuid(), os.getgid()
    _ALL_IDS = 0xFFFFFFFF
    return [
        binary,
        f"--socket-path={cfg.virtiofs_sock}",
        f"--shared-dir={path}",
        "--sandbox=none",
        f"--translate-uid=squash-guest:0:{host_uid}:{_ALL_IDS}",
        f"--translate-gid=squash-guest:0:{host_gid}:{_ALL_IDS}",
    ]
