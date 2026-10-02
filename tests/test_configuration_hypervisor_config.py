"""config -- CWD-derived VM identity, hypervisor.cfg parsing, and the forwarded
SSH port. These are the deterministic pieces the whole tool threads through every
subcommand, so a silent regression here (a mis-parsed toggle, a wrong port,
a mandatory file that slips through) mis-boots every VM.
"""

from __future__ import annotations

import pytest

from hypervisor_helpers import make_cfg

import configuration as config
from configuration import (
    Config, HypervisorCfg, DEFAULT_SSH_FORWARD_PORT, _slugify, select_ssh_port,
)
from checks import HypervisorError


# --- _slugify ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("azzio", "azzio"),
    ("My VM", "my-vm"),
    ("Weird__Name!!", "weird-name"),
    ("...", "vm"),            # nothing usable -> the "vm" fallback
    ("a--b---c", "a-b-c"),    # runs of separators collapse
    ("-trim-", "trim"),       # leading/trailing separators stripped
])
def test_slugify(raw, expected):
    assert _slugify(raw) == expected


# --- vm_name override + proc-name suffix ------------------------------------
# codelis' instance always lives in the fixed dir <workdir>/venv/codelis, so the dir
# basename is 'codelis'. An explicit vm_name lets it still be NAMED after the work dir
# (e.g. 'codelis-claudedebug'), and _proc_name must keep the '-vm' comm suffix intact
# even for such a long name (else `qvm ls`/`stop` -- which match on '-vm' -- break).

def test_proc_name_preserves_vm_suffix_within_15_chars():
    from configuration import _proc_name
    # short name: plain "{vm}-vm"
    assert _proc_name("codelis") == "codelis-vm"
    # long name: slug trimmed so the "-vm" suffix survives the 15-char comm cap
    p = _proc_name("codelis-claudedebug")
    assert p.endswith("-vm") and len(p) <= 15


def test_from_dir_uses_vm_name_from_cfg(tmp_path):
    (tmp_path / "hypervisor.cfg").write_text("vm_name = codelis-claudedebug\n", encoding="utf-8")
    cfg = Config.from_dir(str(tmp_path))
    assert cfg.vm == "codelis-claudedebug"     # NOT the dir basename
    assert cfg.proc.endswith("-vm")


def test_from_dir_vm_name_env_wins_over_cfg(tmp_path, monkeypatch):
    (tmp_path / "hypervisor.cfg").write_text("vm_name = from-cfg\n", encoding="utf-8")
    monkeypatch.setenv("HYPERVISOR_VM_NAME", "from-env")
    cfg = Config.from_dir(str(tmp_path))
    assert cfg.vm == "from-env"


def test_from_dir_no_vm_name_falls_back_to_basename(tmp_path, monkeypatch):
    monkeypatch.delenv("HYPERVISOR_VM_NAME", raising=False)
    cfg = Config.from_dir(str(tmp_path))
    assert cfg.vm == _slugify(tmp_path.name)


def test_vm_name_in_cfg_ignores_env(tmp_path, monkeypatch):
    # The enumeration path (`qvm ls`) must read ONLY the per-dir cfg -- an ambient
    # HYPERVISOR_VM_NAME must not stamp itself onto every listed VM.
    from configuration import _vm_name_in_cfg
    (tmp_path / "hypervisor.cfg").write_text("vm_name = from-cfg\n", encoding="utf-8")
    monkeypatch.setenv("HYPERVISOR_VM_NAME", "from-env")
    assert _vm_name_in_cfg(str(tmp_path)) == "from-cfg"


# --- select_ssh_port --------------------------------------------------------

def _no_running_vms(monkeypatch):
    """Stub the enumeration select_ssh_port consults so a test host that happens to have
    a hypervisor VM running (or none) never perturbs the port maths. Patched on the module
    select_ssh_port actually imports lazily -- hypervisor.vm_instances."""
    import vm_instances
    monkeypatch.setattr(vm_instances, "_running_instances", lambda proc_table=None: [])


def test_select_ssh_port_defaults_to_49350(monkeypatch):
    _no_running_vms(monkeypatch)
    monkeypatch.setattr(config, "_port_in_use", lambda p: False)
    cfg = _make_cfg("testvm")
    assert select_ssh_port(cfg) == DEFAULT_SSH_FORWARD_PORT
    assert DEFAULT_SSH_FORWARD_PORT == 49350


def test_select_ssh_port_bumps_past_a_used_port(monkeypatch):
    _no_running_vms(monkeypatch)
    busy = {DEFAULT_SSH_FORWARD_PORT}
    monkeypatch.setattr(config, "_port_in_use", lambda p: p in busy)
    cfg = _make_cfg("testvm")
    assert select_ssh_port(cfg) == DEFAULT_SSH_FORWARD_PORT + 1


def test_ssh_forward_port_cfg_key_sets_the_base(monkeypatch):
    # The Ssh_Forward_Port key is the manager's floor when no explicit 22:host map is set.
    _no_running_vms(monkeypatch)
    monkeypatch.setattr(config, "_port_in_use", lambda p: False)
    cfg = _make_cfg("testvm", ssh_forward_port=50000)
    assert select_ssh_port(cfg) == 50000


def test_select_ssh_port_increments_per_running_vm(monkeypatch):
    # The core of the port-forward manager: the Nth concurrent VM lands on base+N-1 because
    # each already-running VM's advertised port is treated as claimed (deterministic even
    # before a guest's sshd binds). Two VMs already hold 49350 + 49351 -> a third gets 49352.
    import vm_instances
    monkeypatch.setattr(config, "_port_in_use", lambda p: False)  # nothing bound
    running = [
        {"vm": "a", "pid": 1, "dir": "/vm/a", "ssh_port": 49350},
        {"vm": "b", "pid": 2, "dir": "/vm/b", "ssh_port": 49351},
    ]
    monkeypatch.setattr(vm_instances, "_running_instances", lambda proc_table=None: running)
    assert select_ssh_port(_make_cfg("c", directory="/vm/c")) == 49352
    # A relaunch of an already-running dir keeps its OWN port (its dir is excluded from the
    # claimed set), instead of bumping off itself.
    assert select_ssh_port(_make_cfg("a", directory="/vm/a")) == 49350


def test_select_ssh_port_does_not_climb_past_max(monkeypatch):
    # If the bump loop reached 65536 it would crash socket.bind (OverflowError).
    # With everything up to the max busy, select_ssh_port must fail CLEANLY.
    _no_running_vms(monkeypatch)
    monkeypatch.setattr(config, "_port_in_use", lambda p: True)  # every port busy
    cfg = _make_cfg("testvm", ssh_port=65535)
    with pytest.raises(HypervisorError):
        select_ssh_port(cfg)


def test_port_in_use_treats_out_of_range_as_unusable(monkeypatch):
    # _port_in_use must not leak OverflowError for a port socket.bind rejects.
    assert config._port_in_use(70000) is True


# --- HypervisorCfg parsing + env override -----------------------------------

def test_cfg_defaults_when_no_file(tmp_path):
    import host_resources as hr
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.share_host_gpu is True
    assert hcfg.network == "user"
    # RAM/CPUs/Disk_Size_GB default to 15% of the host, resolved to concrete ints.
    assert hcfg.ram == hr.resolve_percent(15, hr.host_total_ram_mib())
    assert hcfg.cpus == hr.resolve_percent(15, hr.host_cpu_count())
    assert isinstance(hcfg.disk_size_gb, int) and hcfg.disk_size_gb >= 1
    assert hcfg.shared is False
    assert hcfg.clipboard is False                 # new toggle, defaults off
    assert hcfg.usb == []                          # list now, not False
    assert hcfg.secure_shell is False              # renamed from ssh
    assert hcfg.ports == []                        # no forwards by default
    assert hcfg.ssh_port is None


def test_cfg_parses_typed_values(tmp_path):
    (tmp_path / "hypervisor.cfg").write_text(
        "share_host_gpu = false\n"
        "network = none\n"
        "shared = /mnt/host/share\n"
        "usb = /dev/bus/usb/003/004 /dev/sdb\n"
        "ssh = true\n"
        "ram = 8192  # inline comment ignored\n"
        "# a full comment line\n"
    )
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.share_host_gpu is False
    assert hcfg.network == "none"
    assert hcfg.shared == "/mnt/host/share"
    assert hcfg.usb == ["/dev/bus/usb/003/004", "/dev/sdb"]
    assert hcfg.ssh is True
    assert hcfg.ram == 8192


def test_cfg_rejects_invalid_file_value(tmp_path):
    # an out-of-model value must fail loudly at parse time (not silently default).
    (tmp_path / "hypervisor.cfg").write_text("cpus = lots\n")
    with pytest.raises(HypervisorError):
        HypervisorCfg.from_dir(str(tmp_path))


def test_legacy_pre_redesign_cfg_still_loads(tmp_path):
    # A hypervisor.cfg written before the redesign used `sshd` and a boolean
    # `usb`. It must still load: sshd -> ssh, and usb=false -> no passthrough.
    (tmp_path / "hypervisor.cfg").write_text(
        "shared = true\n"
        "sshd = true\n"
        "usb = false\n"
    )
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ssh is True       # migrated from the legacy 'sshd' key
    assert hcfg.usb == []         # legacy boolean 'false' -> empty passthrough
    assert hcfg.shared is True


def test_env_overrides_file(tmp_path, monkeypatch):
    (tmp_path / "hypervisor.cfg").write_text("ram = 8192\nnetwork = user\n")
    monkeypatch.setenv("RAM", "4096")
    monkeypatch.setenv("NETWORK", "none")
    monkeypatch.setenv("SSH", "1")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ram == 4096
    assert hcfg.network == "none"
    assert hcfg.ssh is True


def test_generated_cfg_has_light_comments(tmp_path):
    HypervisorCfg.write(str(tmp_path), config._render_defaults())
    text = (tmp_path / "hypervisor.cfg").read_text()
    # comments are now WANTED (the user reversed the earlier no-comment rule),
    # but minimal: at most one comment line per setting.
    comment_lines = [ln for ln in text.splitlines() if ln.strip().startswith("#")]
    setting_lines = [ln for ln in text.splitlines()
                     if ln.strip() and not ln.strip().startswith("#")]
    assert comment_lines, "generated cfg must carry high-level comments"
    assert len(comment_lines) <= len(setting_lines), "at most one comment per setting"
    # the dropped legacy keys stay dropped.
    assert "kiosk" not in text
    assert "gpu_outputs" not in text
    assert "sshd" not in text                       # renamed to ssh


def test_from_cwd_rejects_malformed_network(tmp_path, monkeypatch):
    # 'potato' is now a VALID interface name; a value with a space is not.
    (tmp_path / "hypervisor.cfg").write_text("network = bad iface\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(HypervisorError):
        Config.from_cwd()


def test_from_cwd_derives_identity_from_dir(tmp_path, monkeypatch):
    d = tmp_path / "My VM"
    d.mkdir()
    monkeypatch.chdir(d)
    cfg = Config.from_cwd()
    assert cfg.vm == "my-vm"
    assert cfg.proc == "my-vm-vm"
    # Identity (vm/proc) comes from the dir, but the disk name is FIXED: always
    # azzio.qcow2, never the folder slug.
    assert cfg.disk.endswith("azzio.qcow2")
    assert "my-vm.qcow2" not in cfg.disk


# --- ISO discovery: REQUIRED, must be a .iso --------------------------------

def test_resolve_iso_requires_an_argument(tmp_path):
    cfg = _make_cfg("d", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_iso("")


def test_resolve_iso_rejects_non_iso_extension(tmp_path):
    (tmp_path / "thing.img").write_text("x")
    cfg = _make_cfg("d", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_iso("thing.img")


def test_resolve_iso_bare_filename_in_dir(tmp_path):
    (tmp_path / "azzio.iso").write_text("x")
    cfg = _make_cfg("d", directory=str(tmp_path))
    assert cfg.resolve_iso("azzio.iso") == str(tmp_path / "azzio.iso")


def test_resolve_iso_missing_named_file_raises(tmp_path):
    cfg = _make_cfg("d", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_iso("nope.iso")


# --- disk discovery for `run`: REQUIRED, must be a .qcow2 -------------------

def test_resolve_run_disk_no_arg_falls_back_to_fixed_disk(tmp_path):
    # No argument -> boot this dir's fixed azzio.qcow2 when it exists (so `hypervisor
    # run` with no args just works after `install`).
    (tmp_path / "azzio.qcow2").write_text("x")
    cfg = _make_cfg("testvm", directory=str(tmp_path))
    assert cfg.resolve_run_disk("") == str(tmp_path / "azzio.qcow2")


def test_resolve_run_disk_no_arg_raises_when_no_disk(tmp_path):
    # No argument AND no azzio.qcow2 on disk -> a clean error (install first), not a
    # boot with nothing.
    cfg = _make_cfg("testvm", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_run_disk("")


def test_resolve_run_disk_rejects_non_qcow2(tmp_path):
    (tmp_path / "disk.raw").write_text("x")
    cfg = _make_cfg("testvm", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_run_disk("disk.raw")


def test_resolve_run_disk_bare_filename_in_dir(tmp_path):
    (tmp_path / "testvm.qcow2").write_text("x")
    cfg = _make_cfg("testvm", directory=str(tmp_path))
    assert cfg.resolve_run_disk("testvm.qcow2") == str(tmp_path / "testvm.qcow2")


def test_resolve_run_disk_missing_named_file_raises(tmp_path):
    cfg = _make_cfg("testvm", directory=str(tmp_path))
    with pytest.raises(HypervisorError):
        cfg.resolve_run_disk("gone.qcow2")


# --- helpers ----------------------------------------------------------------

def _make_cfg(vm: str, *, directory: str = "/d", ssh_port: "int | None" = None,
              ssh_forward_port: int = DEFAULT_SSH_FORWARD_PORT) -> Config:
    # ssh_port (when given) is an EXPLICIT 22:host pin (a legacy bare-number Ports map);
    # left None it stays unset so select_ssh_port falls through to the Ssh_Forward_Port base
    # (the new port-forward manager's floor), which ssh_forward_port sets.
    if ssh_port is not None:
        return make_cfg(directory, vm=vm, ssh_guest_to_host_port_forward=ssh_port)
    return make_cfg(directory, vm=vm, ssh_forward_port=ssh_forward_port)
