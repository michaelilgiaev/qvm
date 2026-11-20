"""Headless boot, `qvm ls`, `qvm view`, and the virtiofs pid file.

These four features are what codelis' unattended cache-build path leans on:

  * `qvm run --headless` boots QEMU (+ virtiofsd) with NO remote-viewer window,
    so an ISO auto-install can run on a box with no display. QEMU STILL creates the
    SPICE socket, so a later `qvm view` can attach.
  * `qvm ls` enumerates every running hypervisor VM on the host (system-wide),
    recovering each VM's dir from /proc/<pid>/cwd and its ssh port from that dir's cfg.
  * `qvm view` opens a viewer on THIS dir's running VM as an ATTACH -- closing
    the window leaves the VM running (unlike `run`, whose viewer close tears it down).
  * virtiofsd's pid is recorded beside its socket (virtiofs.sock.pid) so a warm VM dir
    carries it (part of the codelis cache layout) and is torn down with the socket.

The idiom mirrors test_configuration_hypervisor_terminal_restore.py: a _FakeProc that
captures Popen argv/kwargs, with _spawn_virtiofsd / ConfigWatcher / _maximize_window /
os.path.exists / sys.stdin.isatty monkeypatched so nothing real boots.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from hypervisor_helpers import make_cfg

import checks
import command_line_interface as cli
import virtual_machine as vm
import vm_instances
import vm_lifecycle
from checks import HypervisorError


def _cfg(tmp_path, **overrides):
    return make_cfg(str(tmp_path), **overrides)


class _FakeProc:
    """A Popen stand-in that records argv/kwargs and looks already-exited so _launch's
    _wait_any returns at once and teardown runs. Appends every spawned argv[0] to the
    shared `spawned` list the test inspects."""

    def __init__(self, argv, spawned, **kw):
        self.argv = argv
        self.kw = kw
        self.pid = 4242
        if argv:
            spawned.append(argv[0])

    def poll(self):
        return 0

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0


def _neutralize_launch(monkeypatch, spawned):
    """Fake out every real side effect of _launch: instant spice socket, no virtiofsd,
    no config-watcher thread, no window maximize, non-interactive stdin, and a Popen
    that records into `spawned`."""
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)
    monkeypatch.setattr(vm, "_spawn_virtiofsd", lambda cfg: None)
    monkeypatch.setattr(vm.subprocess, "Popen",
                        lambda argv, **kw: _FakeProc(argv, spawned, **kw))
    monkeypatch.setattr(vm.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(vm.configuration_watcher, "ConfigWatcher",
                        lambda *a, **k: type("W", (), {"start": lambda s: None,
                                                       "stop": lambda s: None})())
    monkeypatch.setattr(vm, "_maximize_window", lambda *a, **k: None)
    monkeypatch.setattr(vm.sys.stdin, "isatty", lambda: False, raising=False)


# --- headless boot: QEMU yes, remote-viewer no -------------------------------

def test_headless_launch_spawns_qemu_but_not_viewer(tmp_path, monkeypatch):
    spawned: list[str] = []
    _neutralize_launch(monkeypatch, spawned)
    cfg = _cfg(tmp_path, shared=False, ssh=False)
    vm._launch(cfg, ["qemu-system-x86_64"], port=None, headless=True)
    assert "qemu-system-x86_64" in spawned, "headless boot must still start QEMU"
    assert "remote-viewer" not in spawned, (
        "headless boot must NOT spawn remote-viewer; got " + repr(spawned))


def test_non_headless_launch_still_spawns_viewer(tmp_path, monkeypatch):
    # Guard against a regression where the headless branch accidentally suppresses the
    # viewer for the NORMAL windowed boot too.
    spawned: list[str] = []
    _neutralize_launch(monkeypatch, spawned)
    cfg = _cfg(tmp_path, shared=False, ssh=False)
    vm._launch(cfg, ["qemu-system-x86_64"], port=None)  # default headless=False
    assert "qemu-system-x86_64" in spawned
    assert "remote-viewer" in spawned, "windowed boot must spawn remote-viewer"


def test_do_run_headless_skips_require_viewer(tmp_path, monkeypatch):
    # headless=True must NOT gate on a viewer being installed (the whole point on a
    # display-less host). Make require_viewer BLOW UP: if do_run(headless=True) reaches
    # it the test fails; the other require_* are stubbed to no-ops.
    def _boom():
        raise AssertionError("require_viewer must NOT be called when headless=True")

    monkeypatch.setattr(checks, "require_viewer", _boom)
    for name in ("require_writable_dir", "require_qemu", "require_ovmf",
                 "require_kvm", "require_not_running"):
        monkeypatch.setattr(checks, name, lambda *a, **k: None)
    captured = {}
    monkeypatch.setattr(vm, "build_qemu_argv", lambda *a, **k: ["qemu-system-x86_64"])
    monkeypatch.setattr(vm, "_write_viewer_ask_quit", lambda *a, **k: None)
    monkeypatch.setattr(vm, "select_ssh_port", lambda cfg: None)

    def _fake_launch(cfg, qemu, port, headless=False):
        captured["headless"] = headless

    monkeypatch.setattr(vm, "_launch", _fake_launch)
    cfg = _cfg(tmp_path, shared=False, ssh=False)
    vm.do_run(cfg, headless=True)
    assert captured.get("headless") is True


def test_do_run_non_headless_requires_viewer(tmp_path, monkeypatch):
    # The mirror: a NORMAL run DOES require a viewer. require_viewer raising must
    # propagate out of do_run when headless is not set.
    class _Stop(Exception):
        pass

    def _boom():
        raise _Stop()

    monkeypatch.setattr(checks, "require_viewer", _boom)
    for name in ("require_writable_dir", "require_qemu", "require_ovmf",
                 "require_kvm", "require_not_running"):
        monkeypatch.setattr(checks, name, lambda *a, **k: None)
    monkeypatch.setattr(vm, "_launch", lambda *a, **k: None)
    cfg = _cfg(tmp_path, shared=False, ssh=False)
    with pytest.raises(_Stop):
        vm.do_run(cfg)  # headless defaults False -> require_viewer runs -> raises


# --- cli dispatch parses --headless ------------------------------------------

def test_cli_dispatch_run_parses_headless(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(vm, "do_run",
                        lambda cfg, **kw: captured.update(kw))
    # resolve_run_disk just needs to return a disk path. Patch it on the CLASS (not the
    # instance): _dispatch_run rebuilds Config from cfg.__dict__, so an instance attr
    # would leak in as a bogus constructor kwarg.
    disk = os.path.join(str(tmp_path), "azzio.qcow2")
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)

    cfg = _cfg(tmp_path, shared=False, ssh=False)
    monkeypatch.setattr(type(cfg), "resolve_run_disk", lambda self, arg: disk, raising=False)

    cli._dispatch_run(cfg, ["azzio.qcow2", "--headless"])
    assert captured.get("headless") is True

    captured.clear()
    cli._dispatch_run(cfg, ["azzio.qcow2"])
    assert captured.get("headless") is False


# --- virtiofs.sock.pid -------------------------------------------------------

def test_virtiofs_pidfile_path_is_socket_plus_pid(tmp_path):
    cfg = _cfg(tmp_path)
    assert cfg.virtiofs_pidfile == cfg.virtiofs_sock + ".pid"


def test_spawn_virtiofsd_writes_pidfile(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, shared=str(tmp_path))
    monkeypatch.setattr(vm, "virtiofsd_argv", lambda cfg: ["virtiofsd", "--x"])
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)

    class _P:
        pid = 9182

        def poll(self):
            return None

    monkeypatch.setattr(vm.subprocess, "Popen", lambda argv, **kw: _P())
    vm._spawn_virtiofsd(cfg)
    with open(cfg.virtiofs_pidfile, encoding="utf-8") as fh:
        assert fh.read().strip() == "9182"


def test_write_pidfile_is_best_effort_on_unwritable(tmp_path):
    # An unwritable path must not raise (a dir we cannot write to must not abort a boot).
    vm._write_pidfile(os.path.join(str(tmp_path), "no_such_dir", "x.pid"), 5)


# --- ls: system-wide running-instance enumeration ----------------------------

def test_running_instances_matches_vm_comms_and_sorts(tmp_path, monkeypatch):
    # Build two real cfg dirs so _cfg_ssh_port reads a genuine hypervisor.cfg.
    d_a = tmp_path / "azzio"
    d_b = tmp_path / "myproj"
    for d, ssh_line in ((d_a, "ssh = true\nssh_guest_to_host_port_forward = 50007\n"),
                        (d_b, "ssh = false\n")):
        os.mkdir(d)
        with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
            fh.write(ssh_line)

    cwds = {222: str(d_b), 333: str(d_a), 555: ""}  # 555 has no cwd -> dropped
    # _running_instances lives in vm_instances and calls _pid_cwd module-locally, so patch
    # it THERE (vm._pid_cwd is only a re-export and would not be seen by the callee).
    monkeypatch.setattr(vm_instances, "_pid_cwd", lambda pid: cwds.get(pid, ""))

    table = [
        (11, "init"),                     # not a VM
        (222, "myproj-vm"),               # VM, ssh off
        (333, "azzio-vm"),                # VM, ssh on 50007
        (444, "qemu-system-x86_64"),      # not a VM (doesn't end -vm)
        (555, "ghost-vm"),                # VM but no cwd -> skipped
    ]
    got = vm_instances._running_instances(table)
    assert [i["vm"] for i in got] == ["azzio", "myproj"], got  # sorted by name
    by = {i["vm"]: i for i in got}
    assert by["azzio"]["ssh_port"] == 50007
    assert by["azzio"]["pid"] == 333
    assert by["myproj"]["ssh_port"] is None  # ssh off -> None


def test_running_instances_uses_vm_name_from_cfg(tmp_path, monkeypatch):
    # A VM whose dir basename is 'codelis' but whose cfg carries vm_name must be LISTED
    # under the vm_name (this is exactly codelis' case: fixed venv/codelis dir named
    # 'codelis-claudedebug'). The comm can be truncated ('codelis-clau-vm'); the dir/cfg
    # is authoritative for the displayed name.
    d = tmp_path / "codelis"
    os.mkdir(d)
    with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
        fh.write("vm_name = codelis-claudedebug\nssh = true\nssh_guest_to_host_port_forward = 49156\n")
    monkeypatch.setattr(vm_instances, "_pid_cwd", lambda pid: str(d) if pid == 900 else "")
    got = vm_instances._running_instances([(900, "codelis-clau-vm")])
    assert [i["vm"] for i in got] == ["codelis-claudedebug"], got
    assert got[0]["ssh_port"] == 49156


def test_running_instances_ignores_ambient_env_vm_name(tmp_path, monkeypatch):
    # Enumeration must read the per-dir cfg only -- a stray HYPERVISOR_VM_NAME in the
    # shell running `qvm ls` must NOT rename every VM to that value.
    d = tmp_path / "myproj"
    os.mkdir(d)
    with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
        fh.write("ssh = false\n")
    monkeypatch.setenv("HYPERVISOR_VM_NAME", "leaked")
    monkeypatch.setattr(vm_instances, "_pid_cwd", lambda pid: str(d) if pid == 901 else "")
    got = vm_instances._running_instances([(901, "myproj-vm")])
    assert [i["vm"] for i in got] == ["myproj"], got


def test_cfg_ssh_port_defaults_when_no_port_line(tmp_path):
    d = tmp_path
    with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
        fh.write("ssh = true\n")  # on, but no explicit port
    assert vm_instances._cfg_ssh_port(str(d)) == vm_instances.DEFAULT_SSH_FORWARD_PORT


def test_cfg_ssh_port_honours_custom_forward_base(tmp_path):
    # A VM installed with `--ssh=PORT` records Ssh_Forward_Port (no explicit 22:host map);
    # ls/enumeration must report THAT base, not the built-in default.
    d = tmp_path
    with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
        fh.write("Secure_Shell = True\nSsh_Forward_Port = 50123\n")
    assert vm_instances._cfg_ssh_port(str(d)) == 50123


def test_cfg_ssh_port_explicit_map_wins_over_forward_base(tmp_path):
    # An explicit 22:host pin always wins over the Ssh_Forward_Port base.
    d = tmp_path
    with open(d / "hypervisor.cfg", "w", encoding="utf-8") as fh:
        fh.write('Secure_Shell = True\nSsh_Forward_Port = 50123\nPorts = "22:51999"\n')
    assert vm_instances._cfg_ssh_port(str(d)) == 51999


def test_cfg_ssh_port_none_when_unreadable(tmp_path):
    assert vm_instances._cfg_ssh_port(str(tmp_path / "does_not_exist")) is None


def test_do_ls_prints_rows(tmp_path, monkeypatch, capsys):
    # do_ls calls _running_instances module-locally in vm_instances -> patch it there.
    monkeypatch.setattr(vm_instances, "_running_instances",
                        lambda: [{"vm": "azzio", "pid": 333, "dir": "/home/u/azzio",
                                  "ssh_port": 50007}])
    vm.do_ls(_cfg(tmp_path))
    out = capsys.readouterr().out
    assert "azzio" in out and "333" in out and "50007" in out and "/home/u/azzio" in out


def test_do_ls_empty(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: [])
    vm.do_ls(_cfg(tmp_path))
    assert "No qvm VMs are running." in capsys.readouterr().out


def test_vm_reexports_ls_names():
    # The CLI dispatch and older call sites use vm.do_ls / vm._running_instances; the
    # split must keep those names pointing at the vm_instances implementations.
    assert vm.do_ls is vm_instances.do_ls
    assert vm._running_instances is vm_instances._running_instances


# --- view: attach-only viewer ------------------------------------------------

def test_do_view_refuses_when_not_running(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "require_viewer", lambda: None)
    monkeypatch.setattr(vm, "is_running", lambda cfg: False)
    with pytest.raises(HypervisorError):
        vm.do_view(_cfg(tmp_path))


def test_do_view_refuses_without_socket(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "require_viewer", lambda: None)
    monkeypatch.setattr(vm, "is_running", lambda cfg: True)
    monkeypatch.setattr(vm.os.path, "exists", lambda p: False)  # no spice socket
    with pytest.raises(HypervisorError):
        vm.do_view(_cfg(tmp_path))


def test_do_view_attaches_and_does_not_stop_vm(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "require_viewer", lambda: None)
    monkeypatch.setattr(vm, "is_running", lambda cfg: True)
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)
    events = {"spawned": 0, "waited": 0}

    class _V:
        def wait(self):
            events["waited"] += 1

        def poll(self):
            return 0

    def _fake_spawn(cfg):
        events["spawned"] += 1
        return _V()

    monkeypatch.setattr(vm, "_spawn_viewer", _fake_spawn)
    # do_view must NOT call do_stop / cleanup: attach semantics leave the VM up. If it
    # tried to stop, this would blow up.
    monkeypatch.setattr(vm, "do_stop",
                        lambda cfg: (_ for _ in ()).throw(AssertionError("view stopped the VM")))
    vm.do_view(_cfg(tmp_path))
    assert events == {"spawned": 1, "waited": 1}


# --- _spawn_viewer wiring ----------------------------------------------------

def test_spawn_viewer_uses_spice_socket_and_devnull_stdin(tmp_path, monkeypatch):
    captured = {}

    def _popen(argv, **kw):
        captured["argv"] = argv
        captured["kw"] = kw
        return object()

    monkeypatch.setattr(vm.subprocess, "Popen", _popen)
    monkeypatch.setattr(vm, "_maximize_window", lambda *a, **k: None)
    cfg = _cfg(tmp_path)
    vm._spawn_viewer(cfg)
    assert captured["argv"][0] == "remote-viewer"
    assert any(a == f"spice+unix://{cfg.spice_sock}" for a in captured["argv"]), captured["argv"]
    assert captured["kw"].get("stdin") is subprocess.DEVNULL


# --- Config.from_dir: a Config for ANY directory, not just cwd ----------------
# `view`/`stop` may target another VM by PID or name; that VM lives in ITS OWN
# directory, so the subcommand must build a Config rooted there. from_cwd is now a
# thin wrapper over from_dir(os.getcwd()); from_dir does the identity derivation for
# an arbitrary directory (vm/proc from the basename, the fixed disk name, the sockets).

def test_from_dir_derives_identity_from_that_directory(tmp_path):
    from configuration import Config, DISK_NAME
    d = tmp_path / "MyProj"
    d.mkdir()
    cfg = Config.from_dir(str(d))
    assert cfg.dir == str(d)
    assert cfg.vm == "myproj"                 # slug of the basename
    assert cfg.proc == "myproj-vm"            # {slug}-vm, capped to 15
    assert cfg.disk == os.path.join(str(d), DISK_NAME)
    assert cfg.spice_sock == os.path.join(str(d), "spice.sock")
    assert cfg.hypervisor_cfg_path == os.path.join(str(d), "hypervisor.cfg")


def test_from_cwd_delegates_to_from_dir(tmp_path, monkeypatch):
    from configuration import Config
    d = tmp_path / "workhere"
    d.mkdir()
    monkeypatch.setattr(vm.os, "getcwd", lambda: str(d), raising=False)
    # from_cwd must produce the same identity from_dir(cwd) would.
    monkeypatch.chdir(d)
    a = Config.from_cwd()
    b = Config.from_dir(str(d))
    assert (a.dir, a.vm, a.proc, a.disk) == (b.dir, b.vm, b.proc, b.disk)


# --- _resolve_target: PID or name -> a running instance dict ------------------
# The backend that `view`/`stop` share. Given a PID string or a VM name, it returns
# the matching running-instance record ({vm,pid,dir,ssh_port}) or dies clearly:
# nothing matched, or (for a name) more than one VM shares it.

def _instances(*recs):
    return list(recs)


def test_resolve_target_by_pid(monkeypatch):
    recs = _instances(
        {"vm": "azzio", "pid": 333, "dir": "/w/azzio", "ssh_port": None},
        {"vm": "myproj", "pid": 444, "dir": "/w/myproj", "ssh_port": None},
    )
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: recs)
    got = vm_instances._resolve_target("444")
    assert got["pid"] == 444 and got["dir"] == "/w/myproj"


def test_resolve_target_by_name(monkeypatch):
    recs = _instances(
        {"vm": "azzio", "pid": 333, "dir": "/w/azzio", "ssh_port": None},
        {"vm": "myproj", "pid": 444, "dir": "/w/myproj", "ssh_port": None},
    )
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: recs)
    got = vm_instances._resolve_target("azzio")
    assert got["pid"] == 333 and got["dir"] == "/w/azzio"


def test_resolve_target_name_is_slugified(monkeypatch):
    # A user may type the directory name with capitals/spaces; match on the slug the
    # VM actually runs under, so "My Proj" resolves the "my-proj" VM.
    recs = _instances({"vm": "my-proj", "pid": 42, "dir": "/w/My Proj", "ssh_port": None})
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: recs)
    assert vm_instances._resolve_target("My Proj")["pid"] == 42


def test_resolve_target_unknown_dies(monkeypatch):
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: [])
    with pytest.raises(HypervisorError):
        vm_instances._resolve_target("nope")


def test_resolve_target_ambiguous_name_dies(monkeypatch):
    # Two VMs in two different dirs whose basenames slug to the SAME name: a bare name
    # is ambiguous, so refuse and make the user disambiguate by PID.
    recs = _instances(
        {"vm": "azzio", "pid": 1, "dir": "/a/azzio", "ssh_port": None},
        {"vm": "azzio", "pid": 2, "dir": "/b/azzio", "ssh_port": None},
    )
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: recs)
    with pytest.raises(HypervisorError) as exc:
        vm_instances._resolve_target("azzio")
    # The two candidate pids should be surfaced so the user can pick one.
    assert "1" in str(exc.value) and "2" in str(exc.value)


def test_resolve_target_pid_that_is_not_a_vm_dies(monkeypatch):
    # A numeric arg that is not a running hypervisor VM's pid must be refused (not
    # silently treated as a name that happens to be all digits).
    recs = _instances({"vm": "azzio", "pid": 333, "dir": "/w/azzio", "ssh_port": None})
    monkeypatch.setattr(vm_instances, "_running_instances", lambda: recs)
    with pytest.raises(HypervisorError):
        vm_instances._resolve_target("999999")


# --- do_view / do_stop targeting another instance by PID or name -------------

def test_do_view_with_target_attaches_to_that_instances_dir(tmp_path, monkeypatch):
    # A running VM lives in target_dir; `view 444` must build a Config for THAT dir and
    # attach its viewer there, NOT the cwd cfg passed in.
    target_dir = tmp_path / "azzio"
    target_dir.mkdir()
    (target_dir / "hypervisor.cfg").write_text("ssh = false\n", encoding="utf-8")
    rec = {"vm": "azzio", "pid": 444, "dir": str(target_dir), "ssh_port": None}
    # do_view stays in virtual_machine but resolves the target via vm_lifecycle._target_cfg,
    # which calls vm_lifecycle._resolve_target -- so patch the resolver THERE (it moved).
    monkeypatch.setattr(vm_lifecycle, "_resolve_target", lambda arg: rec)
    monkeypatch.setattr(checks, "require_viewer", lambda: None)
    monkeypatch.setattr(vm, "is_running", lambda cfg: True)
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)

    seen = {}

    class _V:
        def wait(self):
            seen["waited"] = True

        def poll(self):
            return 0

    def _fake_spawn(cfg):
        seen["dir"] = cfg.dir
        seen["vm"] = cfg.vm
        return _V()

    monkeypatch.setattr(vm, "_spawn_viewer", _fake_spawn)
    # cwd cfg is a DIFFERENT directory; view must ignore it in favour of the target.
    cwd_cfg = _cfg(tmp_path, vm="somewhereelse")
    vm.do_view(cwd_cfg, "444")
    assert seen.get("dir") == str(target_dir)
    assert seen.get("vm") == "azzio"
    assert seen.get("waited") is True


def test_do_stop_with_target_kills_that_instances_proc(tmp_path, monkeypatch):
    target_dir = tmp_path / "azzio"
    target_dir.mkdir()
    (target_dir / "hypervisor.cfg").write_text("ssh = false\n", encoding="utf-8")
    rec = {"vm": "azzio", "pid": 444, "dir": str(target_dir), "ssh_port": None}
    # do_stop + the resolver/liveness/subprocess it uses moved into vm_lifecycle (split for
    # size), so patch them THERE -- that is where do_stop looks these names up.
    monkeypatch.setattr(vm_lifecycle, "_resolve_target", lambda arg: rec)
    # A TARGETED stop (name/pid arg) now judges liveness and kills by the RESOLVED pid --
    # authoritative even for a deleted-dir zombie whose comm no longer matches. Stub os.kill:
    # sig 0 probes report the pid alive until a terminating signal is sent, then dead so the
    # wait loop exits at once. is_running must NOT be consulted on the targeted path.
    sent = []
    def fake_kill(pid, sig):
        if sig == 0:
            if any(p == pid and s != 0 for p, s in sent):
                raise ProcessLookupError
            return
        sent.append((pid, sig))
    monkeypatch.setattr(vm_lifecycle.os, "kill", fake_kill)
    monkeypatch.setattr(vm_lifecycle, "is_running",
                        lambda cfg: (_ for _ in ()).throw(
                            AssertionError("targeted stop must use pid liveness")))
    monkeypatch.setattr(vm_lifecycle.time, "sleep", lambda s: None)

    argvs = []
    monkeypatch.setattr(vm_lifecycle.subprocess, "run", lambda argv, **kw: argvs.append(argv))
    vm.do_stop(_cfg(tmp_path, vm="somewhereelse"), "444")
    # The resolved pid gets a graceful SIGTERM (this is what actually kills a zombie).
    assert (444, vm_lifecycle.signal.SIGTERM) in sent
    # And the TARGET's QEMU proc (azzio-vm) is also pkilled by comm -- belt-and-braces, and
    # never the cwd cfg's proc. A graceful TERM, and NO SIGKILL escalation (it went down in
    # the grace period -- neither an os.kill SIGKILL nor a pkill -KILL).
    assert any(a[:2] == ["pkill", "-TERM"] and "azzio-vm" in a for a in argvs)
    assert not any("-KILL" in a for a in argvs)
    assert not any(s == vm.signal.SIGKILL for _, s in sent)
    # It also proactively TERMs THIS VM's virtiofsd (matched on its per-dir socket) so its
    # shutdown message never leaks to the terminal after the prompt returns.
    assert any(a[:2] == ["pkill", "-TERM"] and any("virtiofsd" in x for x in a)
               for a in argvs)


def test_do_stop_no_arg_uses_cwd_cfg(tmp_path, monkeypatch):
    # Backward compatibility: `qvm stop` with no argument still stops THIS dir's
    # VM (the codelis launcher relies on this -- it cds into the instance and calls
    # `qvm stop`). _resolve_target must NOT be consulted.
    monkeypatch.setattr(vm_lifecycle, "_resolve_target",
                        lambda arg: (_ for _ in ()).throw(AssertionError("must not resolve")))
    states = iter([True, False])
    monkeypatch.setattr(vm_lifecycle, "is_running", lambda cfg: next(states, False))
    monkeypatch.setattr(vm_lifecycle.time, "sleep", lambda s: None)
    argvs = []
    monkeypatch.setattr(vm_lifecycle.subprocess, "run", lambda argv, **kw: argvs.append(argv))
    vm.do_stop(_cfg(tmp_path, vm="thisdir"))
    assert "thisdir-vm" in argvs[0]


def test_do_stop_escalates_to_sigkill_when_qemu_overstays(tmp_path, monkeypatch):
    # If QEMU never dies within the grace period, do_stop escalates to SIGKILL (for both
    # QEMU and the VM's virtiofsd) so `stop` still returns with the VM actually down.
    monkeypatch.setattr(vm_lifecycle, "_resolve_target",
                        lambda arg: (_ for _ in ()).throw(AssertionError("must not resolve")))
    monkeypatch.setattr(vm_lifecycle, "is_running", lambda cfg: True)   # never goes down
    monkeypatch.setattr(vm_lifecycle.time, "sleep", lambda s: None)     # do not actually wait
    argvs = []
    monkeypatch.setattr(vm_lifecycle.subprocess, "run", lambda argv, **kw: argvs.append(argv))
    vm.do_stop(_cfg(tmp_path, vm="stubborn"))
    assert any(a[:2] == ["pkill", "-KILL"] and "stubborn-vm" in a for a in argvs)


def test_do_view_no_arg_uses_cwd_cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(vm, "_resolve_target",
                        lambda arg: (_ for _ in ()).throw(AssertionError("must not resolve")))
    monkeypatch.setattr(checks, "require_viewer", lambda: None)
    monkeypatch.setattr(vm, "is_running", lambda cfg: True)
    monkeypatch.setattr(vm.os.path, "exists", lambda p: True)
    seen = {}

    class _V:
        def wait(self):
            seen["waited"] = True

        def poll(self):
            return 0

    def _spawn(cfg):
        seen["dir"] = cfg.dir
        return _V()

    monkeypatch.setattr(vm, "_spawn_viewer", _spawn)
    vm.do_view(_cfg(tmp_path, vm="thisdir"))
    assert seen.get("dir") == str(tmp_path)


def test_do_stop_with_target_not_running_reports(tmp_path, monkeypatch, capsys):
    # If the resolver somehow points at a pid that is no longer alive by the time we
    # build its cfg, do_stop reports "not running" rather than blindly pkilling.
    target_dir = tmp_path / "azzio"
    target_dir.mkdir()
    (target_dir / "hypervisor.cfg").write_text("ssh = false\n", encoding="utf-8")
    rec = {"vm": "azzio", "pid": 444, "dir": str(target_dir), "ssh_port": None}
    monkeypatch.setattr(vm_lifecycle, "_resolve_target", lambda arg: rec)
    monkeypatch.setattr(vm_lifecycle, "is_running", lambda cfg: False)
    ran = {}
    monkeypatch.setattr(vm_lifecycle.subprocess, "run", lambda argv, **kw: ran.setdefault("argv", argv))
    vm.do_stop(_cfg(tmp_path, vm="somewhereelse"), "444")
    assert "not running" in capsys.readouterr().out
    assert "argv" not in ran            # no pkill fired


# --- CLI dispatch threads the optional PID/name arg through ------------------

def test_cli_view_passes_target_arg(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(vm, "do_view", lambda cfg, arg="": captured.update(arg=arg))
    monkeypatch.setattr(cli.Config, "from_cwd", classmethod(lambda cls: _cfg(tmp_path)))
    assert cli.main(["view", "444"]) == 0
    assert captured.get("arg") == "444"
    captured.clear()
    assert cli.main(["view"]) == 0
    assert captured.get("arg") == ""


def test_cli_stop_passes_target_arg(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(vm, "do_stop", lambda cfg, arg="": captured.update(arg=arg))
    monkeypatch.setattr(cli.Config, "from_cwd", classmethod(lambda cls: _cfg(tmp_path)))
    assert cli.main(["stop", "myproj"]) == 0
    assert captured.get("arg") == "myproj"
    captured.clear()
    assert cli.main(["stop"]) == 0
    assert captured.get("arg") == ""
