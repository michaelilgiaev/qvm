"""Shared test helper for the `hypervisor` suite -- a Config factory.

The hypervisor tests (test_configuration_hypervisor*.py) all build a
configuration.Config rooted at a tmp dir with an overridable
HypervisorCfg. This one factory lives here (beside the tests, importable via the
tests/-dir-on-path set up in conftest.py) so a schema change is made in ONE place
rather than chased through every per-file copy. Ported from the source project's
tests/conftest.make_cfg.
"""

from __future__ import annotations

import os

from configuration import HypervisorCfg, Config, GUEST_SSH_PORT

# The coerced defaults every test Config starts from (matches _CFG_DEFAULTS' types after
# resolve_sizes: bools, resolved int ram/cpus/disk_size_gb, ports/usb lists, shared union).
# One place so a schema change does not have to be chased through the per-file factories.
_HCFG_DEFAULTS = {
    "share_host_gpu": True,
    "network": "user",
    "shared": False,
    "clipboard": False,
    "secure_shell": False,
    "ports": [],
    "ssh_forward_port": 49350,
    "usb": [],
    "fullscreen": False,
    "ask_before_quitting_hypervisor": False,
    "disk_size_gb": 200,
    "ram": 16384,
    "cpus": 16,
    "audio": True,
}

# Pre-redesign override names some tests still pass -> translated to the new field(s), so a
# make_cfg(..., ssh=True) / audio="on" / disk_size="200G" call keeps working unchanged.
_LEGACY_UNIT_TO_MIB = {"M": 1, "G": 1024, "T": 1024 * 1024}


def _translate_legacy_overrides(overrides: dict) -> dict:
    """Map any legacy override kwargs to the new HypervisorCfg field names/values."""
    out = dict(overrides)
    if "ssh" in out:
        out["secure_shell"] = bool(out.pop("ssh"))
    if "ssh_guest_to_host_port_forward" in out:
        port = int(out.pop("ssh_guest_to_host_port_forward"))
        out.setdefault("ports", [(GUEST_SSH_PORT, port)])
    if "audio" in out and isinstance(out["audio"], str):
        out["audio"] = out["audio"].strip().lower() in ("on", "true", "1", "yes")
    if "disk_size" in out:
        val = str(out.pop("disk_size")).strip()
        if val and val[-1].upper() in _LEGACY_UNIT_TO_MIB:
            mib = int(val[:-1]) * _LEGACY_UNIT_TO_MIB[val[-1].upper()]
            out.setdefault("disk_size_gb", max(1, -(-mib // 1024)))
        elif val.isdigit():
            out.setdefault("disk_size_gb", int(val))
    return out


def make_cfg(directory: str, *, vm: str = "testvm", **hcfg_overrides) -> Config:
    """A Config rooted at `directory` with an overridable HypervisorCfg.

    hcfg_overrides take COERCED values (secure_shell=True, ram=8192, usb=["/dev/..."],
    ports=[(22, 49156)], shared="/path" or True/False, audio=True/False). Legacy override
    names (ssh=, ssh_guest_to_host_port_forward=, audio="on", disk_size="200G") are
    translated for back-compat with existing tests.
    """
    vals = dict(_HCFG_DEFAULTS)
    vals.update(_translate_legacy_overrides(hcfg_overrides))
    return Config(
        dir=directory, vm=vm, proc=f"{vm}-vm"[:15],
        # Fixed disk name (azzio.qcow2), not derived from vm slug -- matches
        # Config.from_cwd. Sockets are VISIBLE (no leading dot) -- the hypervisor
        # hides nothing.
        disk=os.path.join(directory, "azzio.qcow2"),
        vars=os.path.join(directory, "OVMF_VARS.4m.fd"),
        shared=os.path.join(directory, "shared"),
        spice_sock=os.path.join(directory, "spice.sock"),
        hypervisor_cfg_path=os.path.join(directory, "hypervisor.cfg"),
        hcfg=HypervisorCfg(**vals),
        code="/usr/share/edk2/x64/OVMF_CODE.4m.fd",
        vars_tmpl="/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    )
