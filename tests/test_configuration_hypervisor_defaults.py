"""configuration_defaults -- the user-wide default overrides for `hypervisor`.

`hypervisor` is per-directory: every VM's settings live in that folder's
hypervisor.cfg, and the base values a fresh `qvm install` starts from are the
hardcoded _CFG_DEFAULTS. This module lets the user override those base defaults ONCE,
globally (~/.config/azzio-hypervisor/defaults.cfg), so every NEW VM inherits them --
the surface the bare-`azzio` TUI's Hypervisor screen drives via `hypervisor
--configure`. A directory's own hypervisor.cfg still wins for that VM.

These tests pin: the load/save/set/reset roundtrip (only schema keys, corrupt file ->
built-ins), that from_dir LAYERS the user defaults under a per-directory cfg and env,
and that the `qvm --configure --set/--status/--reset` dispatch validates,
persists, and reports correctly.
"""

from __future__ import annotations

import pytest

import configuration as config
import configuration_defaults as defaults
import command_line_interface as cli
from configuration import HypervisorCfg


@pytest.fixture(autouse=True)
def _isolate_config_home(tmp_path, monkeypatch):
    """Point XDG_CONFIG_HOME at a tmp dir so no test ever touches the real
    ~/.config/azzio-hypervisor/defaults.cfg. The module reads the path lazily
    (via a function, not a module constant) so this env override takes effect."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdgcfg"))
    # Make sure a stray real defaults file / env override never leaks into a test.
    for env in ("RAM", "CPUS", "NETWORK", "AUDIO", "DISK_SIZE", "DISK_SIZE_GB",
                "PORTS", "SSH", "SSHPORT", "SECURE_SHELL", "CLIPBOARD"):
        monkeypatch.delenv(env, raising=False)
    return tmp_path


# --- configuration_defaults: load / save / set / reset ----------------------

def test_load_missing_file_is_empty():
    assert defaults.load() == {}
    assert defaults.exists() is False


def test_set_then_load_roundtrips_a_valid_key():
    # a lowercase key is accepted (case-insensitive) and stored under its canonical name.
    ok, err = defaults.set_key("ram", "8192")
    assert ok, err
    assert defaults.exists() is True
    assert defaults.load() == {"RAM": "8192"}


def test_set_rejects_an_invalid_value_and_writes_nothing():
    ok, err = defaults.set_key("cpus", "lots")
    assert not ok
    assert "whole number" in err
    assert defaults.load() == {}          # nothing persisted on a bad value
    assert defaults.exists() is False


def test_set_rejects_an_unknown_key():
    ok, err = defaults.set_key("banana", "1")
    assert not ok
    assert "unknown" in err.lower()
    assert defaults.load() == {}


def test_set_accumulates_multiple_keys():
    defaults.set_key("ram", "8192")
    defaults.set_key("network", "none")
    assert defaults.load() == {"RAM": "8192", "Network": "none"}


def test_set_overwrites_an_existing_key():
    defaults.set_key("ram", "8192")
    defaults.set_key("ram", "4096")
    assert defaults.load() == {"RAM": "4096"}


def test_reset_removes_the_file():
    defaults.set_key("ram", "8192")
    assert defaults.exists() is True
    defaults.reset()
    assert defaults.exists() is False
    assert defaults.load() == {}


def test_reset_is_safe_when_absent():
    # never raise just because there is nothing to remove.
    defaults.reset()
    assert defaults.load() == {}


def test_corrupt_defaults_file_degrades_to_empty():
    # A garbage file must not crash a VM launch: it reads as "no overrides".
    path = defaults.defaults_path()
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\x00\x00 not a cfg \xff")
    assert defaults.load() == {}


# --- from_dir LAYERS the user defaults --------------------------------------

def test_from_dir_uses_user_default_when_no_dir_cfg(tmp_path):
    defaults.set_key("ram", "8192")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ram == 8192                # user default beat the built-in 16384


def test_dir_cfg_overrides_user_default(tmp_path):
    defaults.set_key("ram", "8192")
    (tmp_path / "hypervisor.cfg").write_text("ram = 2048\n")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ram == 2048                # the directory's own cfg still wins


def test_env_overrides_user_default(tmp_path, monkeypatch):
    defaults.set_key("ram", "8192")
    monkeypatch.setenv("RAM", "1024")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ram == 1024                # env still beats everything


def test_unset_keys_keep_built_in_defaults(tmp_path):
    import host_resources as hr
    defaults.set_key("ram", "8192")
    hcfg = HypervisorCfg.from_dir(str(tmp_path))
    assert hcfg.ram == 8192
    # untouched -> built-in default (15% of host CPUs, resolved).
    assert hcfg.cpus == hr.resolve_percent(15, hr.host_cpu_count())


# --- the `qvm --configure` dispatch ----------------------------------

def test_configure_set_persists_a_valid_value(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--configure", "--set", "ram", "8192"])
    assert rc == 0
    assert defaults.load() == {"RAM": "8192"}


def test_configure_set_rejects_a_bad_value_nonzero_and_writes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--configure", "--set", "cpus", "lots"])
    assert rc != 0
    assert defaults.load() == {}
    err = capsys.readouterr().err
    assert "CPUs" in err                   # error names the canonical key


def test_configure_status_prints_effective_defaults(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    defaults.set_key("ram", "8192")
    rc = cli.main(["--configure", "--status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "RAM = 8192" in out             # the override shows (canonical key)
    assert "CPUs = 15%" in out             # a built-in default still shows (unquoted percent)


def test_configure_reset_clears_overrides(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    defaults.set_key("ram", "8192")
    rc = cli.main(["--configure", "--reset"])
    assert rc == 0
    assert defaults.exists() is False


def test_configure_set_does_not_need_a_vm_directory(tmp_path, monkeypatch):
    # --configure edits the GLOBAL defaults; it must not require a resolvable
    # per-directory VM (an empty scratch dir has no disk/iso), so it must work
    # from anywhere without raising.
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    rc = cli.main(["--configure", "--set", "audio", "off"])
    assert rc == 0
    assert defaults.load() == {"Audio": "off"}
