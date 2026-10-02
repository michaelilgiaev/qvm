"""do_share_offline -- the powered-off-disk editor's guard.

This path has no host-independent happy route (it needs qemu-nbd, sudo, a real
Btrfs guest), but its FIRST action is a precondition: the disk for this directory
must exist. That guard is pure and must fail CLEANLY (HypervisorError -> the
'qvm: ...' exit-1 path), never crash. A prior refactor that made
resolve_run_disk() require an argument left this call site stale and turned the
missing-disk case into an uncaught TypeError; this pins it shut.
"""

from __future__ import annotations

import os

import pytest

from hypervisor_helpers import make_cfg

import virtual_machine as vm
import vm_share
from checks import HypervisorError


def test_share_offline_missing_disk_raises_cleanly(tmp_path):
    cfg = make_cfg(str(tmp_path))  # no testvm.qcow2 on disk
    with pytest.raises(HypervisorError):
        vm.do_share_offline(cfg)


def test_install_shared_ssh_makes_an_empty_share_no_authorized_keys(tmp_path, monkeypatch):
    # `install --shared --ssh` must create the share as an EMPTY directory. It must
    # NOT stage the host's public key into shared/authorized_keys -- the guest owns
    # its own key setup, and a leftover authorized_keys survived `rm -rf shared/*`
    # re-installs, silently re-injecting a stale host key. Pin the share empty.
    (tmp_path / "os.iso").write_bytes(b"")  # a resolvable, readable ISO in-dir
    monkeypatch.setattr(vm.checks, "require_qemu", lambda: None)
    monkeypatch.setattr(vm.checks, "require_ovmf", lambda cfg: None)
    monkeypatch.setattr(vm.checks, "require_free_space", lambda cfg: None)
    monkeypatch.setattr(vm, "_qemu_img_create", lambda cfg: open(cfg.disk, "wb").close())
    # NVRAM copy would read a host template that isn't present under tmp; skip it.
    monkeypatch.setattr(vm.shutil, "copyfile", lambda src, dst: open(dst, "wb").close())

    cfg = make_cfg(str(tmp_path))
    vm.do_install(cfg, "os.iso", shared=True, ssh=True)

    assert os.path.isdir(cfg.shared)                                  # share created
    assert os.listdir(cfg.shared) == []                              # and it is empty
    assert not os.path.exists(os.path.join(cfg.shared, "authorized_keys"))


def test_guest_fstab_line_is_virtiofs_not_9p():
    # The baked-in guest mount uses virtiofs (mount tag "shared"), NOT 9p. virtiofs
    # needs no trans=/version= options and no modules-load entry (the driver is
    # in-tree in modern kernels), so the line is a plain virtiofs fstab entry.
    # (_guest_fstab_line moved into vm_share when the share flow was split out.)
    line = vm_share._guest_fstab_line("main")
    fields = line.split()
    assert fields[0] == "shared"                 # source == the virtiofs mount tag (opaque, lowercase)
    assert fields[1] == "/home/main/Shared"      # target (the guest mountpoint dir)
    assert fields[2] == "virtiofs"               # fstype
    assert "nofail" in fields[3].split(",")      # never blocks boot if absent
    assert "9p" not in line and "trans=virtio" not in line
