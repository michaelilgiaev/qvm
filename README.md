<p align="center">
  <img src="assets/qvm_title_627x230.png" alt="qvm">
</p>

QEMU VM, one per directory. Run `qvm` inside a directory and that directory IS the VM: its
name, disk, UEFI NVRAM, shared folder and forwarded SSH port all derive from the folder you
are in, and every setting lives in a per-directory `hypervisor.cfg`.

## Setup

Documentation only covers Arch-based systems.

```
sudo pacman --sync --refresh --needed --noconfirm - < packages_x86_64 \
    && ./compile.sh \
    && sudo install -m 755 output/qvm /usr/bin/ \
    && sudo install -m 644 libraries/completion.bash /usr/share/bash-completion/completions/qvm
```
