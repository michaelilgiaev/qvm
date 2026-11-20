"""vm_share.py - the `share` subcommand: print guest-side mount instructions, or
edit a powered-off guest disk offline (Btrfs @/@home) to wire the virtiofs share in.

Split out of virtual_machine.py (which kept growing past the module size budget): the
share flow -- its instruction text, the offline qemu-nbd/btrfs disk edit, and the
sudo/block-device helpers it alone uses -- is a self-contained concern, distinct from
the install/run/status/stop VM lifecycle. virtual_machine re-exports do_share (and its
siblings) so `vm.do_share` still resolves at the single call site in
command_line_interface.py. The flat sibling import below mirrors the rest of the
modules (see configuration.py for the full rationale).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

# Flat sibling imports: the modules live directly in libraries/ (no package).
import checks  # noqa: E402  (after virtual_machine's sys.path bootstrap)
from checks import die  # noqa: E402
from configuration import Config  # noqa: E402


def _guest_fstab_line(guest_user: str) -> str:
    """The /etc/fstab line that auto-mounts the share inside the guest, via virtiofs.
    PURE. virtiofs needs no trans=/version= options and no modules-load entry (the
    driver is in-tree in modern kernels), so this is a plain virtiofs entry with
    'nofail' so a VM booted without the share still boots. The source field is the
    mount tag "shared" advertised by the vhost-user-fs device (an opaque host<->guest
    identifier -- it stays lowercase; only the on-disk dir / mountpoint is "Shared")."""
    return f"shared  /home/{guest_user}/Shared  virtiofs  nofail  0 0"


# --- share -------------------------------------------------------------------
def do_share(cfg: Config, arg: str) -> None:
    if arg == "--offline":
        do_share_offline(cfg)
    else:
        do_share_print()


def do_share_print() -> None:
    print(_SHARE_TEXT)


_SHARE_TEXT = """\
Run THESE commands ONCE INSIDE THE GUEST to auto-mount the host ./shared folder
at ~/Shared on every boot (any modern Linux guest -- the virtiofs driver is
in-tree, so no module or package is needed):

  sudo mkdir -p ~/Shared
  echo "shared  $HOME/Shared  virtiofs  nofail  0 0" | sudo tee -a /etc/fstab
  sudo mount -a

After that it appears at ~/Shared on every boot, owned by your guest user.
(virtiofsd preserves the host uid/gid; when host and guest both use uid 1000,
ownership lines up. An Azzio guest already auto-mounts it via the shipped
home-main-Shared.mount systemd unit -- no need to run the above.)

----------------------------------------------------------------------------
For a SMOOTH, auto-1920x1080 desktop, the GUEST also needs (once):

  # 1. spice-vdagent -- REQUIRED for auto-resolution. Without it the viewer
  #    window maximizes but the guest stays letterboxed at its boot mode.
  sudo pacman -S spice-vdagent
  sudo systemctl enable --now spice-vdagentd

  # 2. virtio/VirGL GPU driver active (host offloads GL to the RTX 4070).
  #    Verify -- must say "virgl", NOT "llvmpipe":
  glxinfo | grep -i virgl

  # 3. Cinnamon/Muffin smoothness (stops juddering on the paravirtual GPU) --
  #    add to /etc/environment, then re-login:
  echo -e 'CLUTTER_VBLANK=none\\nCOGL_DRIVER=gl3' | sudo tee -a /etc/environment"""


def do_share_offline(cfg: Config) -> None:
    """Edit the powered-off guest disk from the host via qemu-nbd (Btrfs @/@home
    only -- Arch/Manjaro Calamares layout). Refuses anything else, since editing
    an unknown guest layout offline risks corrupting it."""
    guest_uid = os.environ.get("GUEST_UID", "1000")
    guest_gid = os.environ.get("GUEST_GID", "1000")
    # The guest's login name inside the VM. Defaults to the Azzio guest account (`main`,
    # the autologin user the ISO provisions), but is overridable for a differently-named
    # guest -- so this is NOT a host-side /home/<user> hard-code (it names the GUEST's home
    # inside its own disk, mirroring the adjacent GUEST_UID/GID overrides).
    guest_user = os.environ.get("GUEST_USER", "main")
    mountpoint = f"/home/{guest_user}/Shared"
    fstab_line = _guest_fstab_line(guest_user)

    disk = cfg.disk
    if not os.path.isfile(disk):
        die(f"no disk to edit: {disk} -- run 'qvm install <iso>' first")
    if shutil.which("qemu-nbd") is None:
        die("qemu-nbd missing -- sudo pacman -S qemu-img")
    checks.require_not_running(cfg)

    _sudo(["modprobe", "nbd", "max_part=16"])
    nbd = _free_nbd()
    if not nbd:
        die("no free /dev/nbdN device available")

    mnt = None
    connected = False
    try:
        print(f"Attaching {disk} on {nbd} ...")
        _sudo(["qemu-nbd", "--disconnect", nbd], quiet=True)
        _sudo(["qemu-nbd", f"--connect={nbd}", disk])
        connected = True
        time.sleep(1)
        _sudo(["partprobe", nbd], quiet=True)

        rootpart = f"{nbd}p2"
        if not _is_block(rootpart):
            rootpart = f"{nbd}p1"
        if not _is_block(rootpart):
            die(f"no candidate root partition on {nbd}")
        if _fstype(rootpart) != "btrfs":
            die(
                "guest root is not the Btrfs @/@home layout this editor expects -- "
                "use 'qvm share' (mount from inside the guest) instead"
            )

        mnt = subprocess.run(
            ["mktemp", "-d"], check=True, capture_output=True, text=True
        ).stdout.strip()

        # 1. /etc/fstab (root subvolume @). virtiofs needs NO modules-load entry --
        # the virtiofs driver is in-tree in modern kernels, so unlike 9p there is
        # nothing to force-load at boot; the fstab line alone makes it mount.
        _sudo(["mount", "-o", "subvol=@", rootpart, mnt])
        fstab = os.path.join(mnt, "etc/fstab")
        if _grep_mount(fstab, mountpoint):
            print(f"fstab: entry for {mountpoint} already present.")
        else:
            print("fstab: adding shared-folder mount (virtiofs).")
            _sudo_append(
                fstab,
                '\n# host<->guest shared folder (virtiofs, mount tag "shared")\n'
                + fstab_line
                + "\n",
            )
        _sudo(["umount", mnt])

        # 2. create the mountpoint (home subvolume @home)
        _sudo(["mount", "-o", "subvol=@home", rootpart, mnt])
        if os.path.isdir(os.path.join(mnt, guest_user)):
            _sudo(["mkdir", "-p", os.path.join(mnt, guest_user, "Shared")])
            _sudo(["chown", f"{guest_uid}:{guest_gid}",
                   os.path.join(mnt, guest_user, "Shared")])
            print(f"mountpoint: {mountpoint} ready (owner {guest_uid}:{guest_gid}).")
        else:
            die(f"guest /home/{guest_user} not found in @home subvolume")
        _sudo(["umount", mnt])
    finally:
        if mnt:
            _sudo(["umount", "-R", mnt], quiet=True)
            try:
                os.rmdir(mnt)
            except OSError:
                pass
        if connected:
            _sudo(["qemu-nbd", "--disconnect", nbd], quiet=True)

    print()
    print(f"Done. Boot with 'qvm run' -- the share appears at {mountpoint} in the guest.")


# --- sudo / block-device helpers (used only by the offline share edit) -------
def _sudo(argv: list[str], quiet: bool = False) -> int:
    kw = {}
    if quiet:
        kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    return subprocess.run(["sudo", *argv], **kw).returncode


def _sudo_append(path: str, text: str) -> None:
    subprocess.run(["sudo", "tee", "-a", path], input=text, text=True,
                   stdout=subprocess.DEVNULL, check=True)


def _sudo_write(path: str, text: str) -> None:
    subprocess.run(["sudo", "tee", path], input=text, text=True,
                   stdout=subprocess.DEVNULL, check=True)


def _grep_mount(fstab: str, mountpoint: str) -> bool:
    """True if an uncommented fstab line already mounts `mountpoint`."""
    try:
        out = subprocess.run(
            ["sudo", "grep", "-qE", rf"^[^#]*[[:space:]]{mountpoint}[[:space:]]", fstab]
        )
        return out.returncode == 0
    except FileNotFoundError:
        return False


def _free_nbd() -> str:
    """Pick a FREE /dev/nbdN (size 0), matching share.sh's loop."""
    import glob as _glob
    for d in sorted(_glob.glob("/dev/nbd*")):
        name = os.path.basename(d)
        try:
            with open(f"/sys/class/block/{name}/size") as fh:
                if fh.read().strip() == "0":
                    return d
        except OSError:
            continue
    return ""


def _is_block(path: str) -> bool:
    try:
        import stat
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def _fstype(part: str) -> str:
    try:
        return subprocess.run(
            ["lsblk", "-no", "FSTYPE", part], capture_output=True, text=True
        ).stdout.strip()
    except FileNotFoundError:
        return ""
