"""_auto_install_iso -- the empty-disk installer-ISO auto-attach decision.

REGRESSION GUARD. The old code auto-attached the single installer ISO when the
system disk was still EMPTY (never installed), so `qvm run azzio.qcow2`
on a fresh disk booted the installer instead of hanging at the UEFI shell. A
refactor that made `run` demand an explicit .qcow2 dropped that logic; this pins
it back.

The decision is PURE: given the resolved disk, an explicit --iso (or ""), and the
directory's single-ISO discovery, it returns the ISO to attach as a CD-ROM (or
""). do_run keeps the host checks and the launch; only this choice is tested here.

Contract:
  * explicit install_iso always wins (repair / reinstall an already-full disk).
  * no explicit iso + EMPTY disk (<1 MiB) + exactly one *.iso in dir -> that iso.
  * no explicit iso + NON-empty disk -> "" (normal boot; never surprise-attach).
  * no explicit iso + empty disk + zero-or-many isos -> "" (nothing to pick).
"""

from __future__ import annotations

from hypervisor_helpers import make_cfg

import virtual_machine as vm


def _cfg(tmp_path):
    return make_cfg(str(tmp_path))


def _empty_disk(tmp_path) -> str:
    """A 'never installed' qcow2: a few hundred bytes, well under the 1 MiB floor."""
    disk = str(tmp_path / "testvm.qcow2")
    with open(disk, "wb") as fh:
        fh.write(b"\0" * 4096)
    return disk


def _full_disk(tmp_path) -> str:
    """A disk that clearly holds an installed system: > 1 MiB allocated."""
    disk = str(tmp_path / "testvm.qcow2")
    with open(disk, "wb") as fh:
        fh.write(b"\0" * (2 * 1024 * 1024))
    return disk


def test_empty_disk_one_iso_auto_attaches(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _empty_disk(tmp_path)
    iso = tmp_path / "azzio.iso"
    iso.write_text("x")
    assert vm._auto_install_iso(cfg, "", disk) == str(iso)


def test_empty_disk_no_iso_attaches_nothing(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _empty_disk(tmp_path)
    assert vm._auto_install_iso(cfg, "", disk) == ""


def test_empty_disk_many_isos_attaches_nothing(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _empty_disk(tmp_path)
    (tmp_path / "a.iso").write_text("x")
    (tmp_path / "b.iso").write_text("x")
    # ambiguous -> find_iso() returns "" -> no surprise attach.
    assert vm._auto_install_iso(cfg, "", disk) == ""


def test_full_disk_never_auto_attaches(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _full_disk(tmp_path)
    (tmp_path / "azzio.iso").write_text("x")  # present, but disk is installed
    assert vm._auto_install_iso(cfg, "", disk) == ""


def test_explicit_iso_wins_even_on_full_disk(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _full_disk(tmp_path)
    explicit = str(tmp_path / "repair.iso")
    assert vm._auto_install_iso(cfg, explicit, disk) == explicit


def test_explicit_iso_wins_over_auto_discovery(tmp_path):
    cfg = _cfg(tmp_path)
    disk = _empty_disk(tmp_path)
    (tmp_path / "discovered.iso").write_text("x")
    explicit = str(tmp_path / "explicit.iso")
    # explicit path is returned verbatim; discovery is not consulted.
    assert vm._auto_install_iso(cfg, explicit, disk) == explicit
