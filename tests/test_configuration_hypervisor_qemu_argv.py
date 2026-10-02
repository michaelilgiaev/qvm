"""build_qemu_argv -- the pure QEMU command-line assembler extracted from do_run.

do_run() does the host checks, filesystem setup, and process launch; the actual
QEMU argv list is built by build_qemu_argv(), which is PURE: it takes already
resolved inputs (the disk path, the display/gpu args, the iso args, the forwarded
ssh port) and returns the argv list. No process launch, no filesystem mutation.
That purity is what lets us pin the command here without a real host.

These tests pin the STRUCTURE that matters (identity, the pflash + disk drives,
and the cfg/port-gated blocks: iso, audio, shared virtiofs, networking, USB, and
the ssh hostfwd), not the exact byte-for-byte flag soup -- so a deliberate device
tweak does not force a rewrite, but a dropped disk drive or a mis-gated block is
caught.
"""

from __future__ import annotations

from hypervisor_helpers import make_cfg

import virtual_machine as vm


def _cfg(tmp_path, **cfg_overrides):
    """A Config rooted at tmp_path with an overridable HypervisorCfg (coerced types)."""
    return make_cfg(str(tmp_path), **cfg_overrides)


def _pairs(argv, flag):
    """Every value that immediately follows `flag` in argv (e.g. all -device values)."""
    return [argv[i + 1] for i, tok in enumerate(argv) if tok == flag and i + 1 < len(argv)]


def test_returns_a_list_starting_with_the_qemu_binary(tmp_path):
    cfg = _cfg(tmp_path)
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert isinstance(argv, list)
    assert argv[0] == "qemu-system-x86_64"


def test_identity_carries_vm_and_proc(tmp_path):
    cfg = _cfg(tmp_path)
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert f"{cfg.vm},process={cfg.proc}" in _pairs(argv, "-name")


def test_pflash_and_disk_drives_present(tmp_path):
    cfg = _cfg(tmp_path)
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    drives = _pairs(argv, "-drive")
    # UEFI CODE (readonly) + VARS (writable) pflash, and the qcow2 system disk.
    assert any("if=pflash" in d and "readonly=on" in d and cfg.code in d for d in drives)
    assert any("if=pflash" in d and cfg.vars in d for d in drives)
    assert any(cfg.disk in d and "format=qcow2" in d for d in drives)


def test_ram_and_cpus_from_cfg(tmp_path):
    cfg = _cfg(tmp_path, ram="8192", cpus="4")
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert "8192" in _pairs(argv, "-m")
    assert any(s.startswith("4,sockets=1,cores=4") for s in _pairs(argv, "-smp"))


def test_gpu_and_iso_args_are_spliced_in_verbatim(tmp_path):
    cfg = _cfg(tmp_path)
    gpu = ["-device", "virtio-vga", "-display", "none"]
    iso = ["-device", "ich9-ahci,id=sata"]
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=gpu, iso_args=iso, port_maps=None)
    joined = " ".join(argv)
    assert "virtio-vga" in joined and "ich9-ahci,id=sata" in joined


def test_audio_present_when_on_absent_when_off(tmp_path):
    on = _cfg(tmp_path, audio=True)
    off = _cfg(tmp_path, audio=False)
    argv_on = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    argv_off = vm.build_qemu_argv(off, disk=off.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert any("pipewire" in a for a in _pairs(argv_on, "-audiodev"))
    assert not any("pipewire" in a for a in _pairs(argv_off, "-audiodev"))


def test_clipboard_channel_present_only_when_enabled(tmp_path):
    # The SPICE vdagent channel (clipboard sharing) rides a spicevmc chardev exposed on
    # the com.redhat.spice.0 port -- present ONLY when Clipboard is on. The -spice display
    # itself is always there (the viewer needs it); only the channel is gated.
    off = _cfg(tmp_path, clipboard=False)
    on = _cfg(tmp_path, clipboard=True)
    argv_off = vm.build_qemu_argv(off, disk=off.disk, gpu_args=[], iso_args=[], port_maps=None)
    argv_on = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert any(a.startswith("unix=on") for a in _pairs(argv_off, "-spice"))  # display always on
    assert not any("spicevmc" in c for c in _pairs(argv_off, "-chardev"))
    assert not any("com.redhat.spice.0" in d for d in _pairs(argv_off, "-device"))
    assert any("spicevmc" in c and "vdagent" in c for c in _pairs(argv_on, "-chardev"))
    assert any("com.redhat.spice.0" in d for d in _pairs(argv_on, "-device"))


def test_shared_virtiofs_present_only_when_shared_enabled(tmp_path):
    off = _cfg(tmp_path, shared=False)
    on = _cfg(tmp_path, shared=True)   # True == the working ./Shared dir
    argv_off = vm.build_qemu_argv(off, disk=off.disk, gpu_args=[], iso_args=[], port_maps=None)
    argv_on = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    # OFF: no virtiofs device, and (crucially) no leftover 9p transport either.
    assert not any("vhost-user-fs" in d for d in _pairs(argv_off, "-device"))
    assert not any("virtio-9p" in d for d in _pairs(argv_off, "-device"))
    # ON: exactly one vhost-user-fs device advertising the stable "shared" tag.
    vfs = [d for d in _pairs(argv_on, "-device") if "vhost-user-fs-pci" in d]
    assert len(vfs) == 1
    assert "tag=shared" in vfs[0]
    # ...backed by a vhost-user chardev socket at cfg.virtiofs_sock.
    assert any(f"path={on.virtiofs_sock}" in c and "socket" in c
               for c in _pairs(argv_on, "-chardev"))
    # ...and never the old 9p transport.
    assert not any("virtio-9p" in d for d in _pairs(argv_on, "-device"))


def test_shared_virtiofs_needs_shared_memfd_backend(tmp_path):
    # virtiofs REQUIRES a shared memory-backend the guest and daemon map together.
    # It is present ONLY when shared is on, sized to guest RAM, and wired to a NUMA
    # node; with shared off the command must be byte-identical to today (no memdev,
    # no -numa) so non-shared VMs are untouched.
    off = _cfg(tmp_path, shared=False, ram="8192")
    on = _cfg(tmp_path, shared=True, ram="8192")
    argv_off = vm.build_qemu_argv(off, disk=off.disk, gpu_args=[], iso_args=[], port_maps=None)
    argv_on = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert "-numa" not in argv_off
    assert not any("memory-backend-memfd" in o for o in _pairs(argv_off, "-object"))
    memfd = [o for o in _pairs(argv_on, "-object") if "memory-backend-memfd" in o]
    assert len(memfd) == 1
    assert "share=on" in memfd[0] and "size=8192M" in memfd[0]
    assert any("memdev=mem" in n for n in _pairs(argv_on, "-numa"))


def test_shared_custom_path_points_daemon_not_qemu(tmp_path):
    # With virtiofs the HOST path is exported by the virtiofsd daemon, not named in
    # the QEMU argv (QEMU only sees the vhost-user socket). So the custom path must
    # NOT leak into the QEMU command; it belongs to the daemon argv instead.
    custom = "/mnt/host/project"
    cfg = _cfg(tmp_path, shared=custom)
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert not any(custom in a for a in argv)
    # the daemon, however, IS pointed at the custom path.
    daemon = vm.virtiofsd_argv(cfg)
    assert f"--shared-dir={custom}" in daemon or ("--shared-dir" in daemon
           and custom in daemon)


def test_hostfwd_present_iff_port_given(tmp_path):
    cfg = _cfg(tmp_path)
    no_port = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    with_port = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=[(22, 49155)])
    assert not any("hostfwd" in n for n in _pairs(no_port, "-netdev"))
    assert any("hostfwd=tcp::49155-:22" in n for n in _pairs(with_port, "-netdev"))


def test_multiple_port_maps_each_become_a_hostfwd(tmp_path):
    # Ports = "22:49156, 1500:49157" -> a hostfwd per map (host->guest), all on the one
    # user netdev. Each is tcp::<host>-:<guest>.
    cfg = _cfg(tmp_path)
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[],
                              port_maps=[(22, 49156), (1500, 49157)])
    netdev = " ".join(_pairs(argv, "-netdev"))
    assert "hostfwd=tcp::49156-:22" in netdev
    assert "hostfwd=tcp::49157-:1500" in netdev


def test_network_user_has_a_nic_none_has_none(tmp_path):
    user = _cfg(tmp_path, network="user")
    none = _cfg(tmp_path, network="none")
    argv_user = vm.build_qemu_argv(user, disk=user.disk, gpu_args=[], iso_args=[], port_maps=None)
    argv_none = vm.build_qemu_argv(none, disk=none.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert any("virtio-net-pci" in d for d in _pairs(argv_user, "-device"))
    assert any(n.startswith("user,") for n in _pairs(argv_user, "-netdev"))
    assert not any("virtio-net-pci" in d for d in _pairs(argv_none, "-device"))
    assert "-netdev" not in argv_none


def test_network_interface_bridges_onto_that_interface(tmp_path):
    cfg = _cfg(tmp_path, network="eno1")
    argv = vm.build_qemu_argv(cfg, disk=cfg.disk, gpu_args=[], iso_args=[], port_maps=None)
    # a named interface bridges: a bridge netdev naming eno1, plus a virtio NIC.
    assert any("bridge" in n and "eno1" in n for n in _pairs(argv, "-netdev"))
    assert any("virtio-net-pci" in d for d in _pairs(argv, "-device"))


def test_hostfwd_only_applies_to_user_mode(tmp_path):
    # An interface bridge does not carry the user-mode hostfwd (there is no
    # user netdev to hang it on); the port is only meaningful for network=user.
    iface = _cfg(tmp_path, network="eno1")
    argv = vm.build_qemu_argv(iface, disk=iface.disk, gpu_args=[], iso_args=[], port_maps=[(22, 49155)])
    assert not any("hostfwd" in n for n in _pairs(argv, "-netdev"))


def test_usb_passthrough_absent_when_empty(tmp_path):
    off = _cfg(tmp_path, usb=[])
    argv_off = vm.build_qemu_argv(off, disk=off.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert not any("qemu-xhci" in d for d in _pairs(argv_off, "-device"))
    assert not any("usb-host" in d for d in _pairs(argv_off, "-device"))


def test_usb_passthrough_one_device(tmp_path):
    on = _cfg(tmp_path, usb=["/dev/bus/usb/003/004"])
    argv = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    assert any("qemu-xhci" in d for d in _pairs(argv, "-device"))
    devs = _pairs(argv, "-device")
    assert any("usb-host" in d and "hostdevice=/dev/bus/usb/003/004" in d for d in devs)


def test_usb_passthrough_many_devices_each_get_a_host_device(tmp_path):
    paths = ["/dev/bus/usb/003/004", "/dev/bus/usb/001/002"]
    on = _cfg(tmp_path, usb=paths)
    argv = vm.build_qemu_argv(on, disk=on.disk, gpu_args=[], iso_args=[], port_maps=None)
    devs = _pairs(argv, "-device")
    for p in paths:
        assert any("usb-host" in d and f"hostdevice={p}" in d for d in devs), p
    # exactly one controller regardless of device count.
    assert sum("qemu-xhci" in d for d in devs) == 1
