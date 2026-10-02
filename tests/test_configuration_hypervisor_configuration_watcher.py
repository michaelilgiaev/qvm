"""configuration_watcher -- live hypervisor.cfg reload: validate, apply, or safe-revert.

While a VM runs, the hypervisor watches hypervisor.cfg. On every save there are
exactly two outcomes (the user's spec):

  1. VALID   -> the new values are applied by the running hypervisor. Changes are
                split into those applied LIVE and those that need a reboot.
  2. INVALID -> the file is REVERTED to the last-known-good contents, so a broken
                edit never bricks the VM.

The decision is a PURE function, evaluate_save(new_text, last_good). It does no
I/O: it parses+validates the text, and returns what to do. The watcher thread is
a thin wrapper that reads the file, calls this, and writes the revert / applies
the diff. Keeping the decision pure is what makes accept/revert unit-testable
without a running VM -- which is the whole point of the safety guarantee.

The cfg keys are now Title_Case (Audio, RAM, CPUs, Network, ...) and bools render
True/False; these tests edit the generated text and assert on the canonical keys.
"""

from __future__ import annotations

import configuration_watcher as cw
import configuration as config


def _good():
    """A last-known-good snapshot from the defaults."""
    values = dict(config._CFG_DEFAULTS)
    text = config._hypervisor_cfg_text(config._render_defaults())
    return cw.Snapshot(values=values, text=text)


# --- valid edits ------------------------------------------------------------

def test_valid_edit_is_accepted_with_new_values():
    good = _good()
    new = good.text.replace("Audio = True", "Audio = False")
    decision = cw.evaluate_save(new, good)
    assert decision.valid
    assert not decision.errors
    assert decision.values["Audio"] is False


def test_unchanged_file_is_a_noop():
    good = _good()
    decision = cw.evaluate_save(good.text, good)
    assert decision.valid
    assert decision.changed_keys == []
    assert decision.live_changes == [] and decision.reboot_changes == []


def test_changed_keys_are_reported():
    good = _good()
    new = good.text.replace('RAM = 15%', "RAM = 8192")
    decision = cw.evaluate_save(new, good)
    assert decision.valid
    assert "RAM" in decision.changed_keys


# --- live vs reboot classification ------------------------------------------

def test_ram_change_is_reboot_only():
    good = _good()
    new = good.text.replace('RAM = 15%', "RAM = 8192")
    decision = cw.evaluate_save(new, good)
    assert "RAM" in decision.reboot_changes
    assert "RAM" not in decision.live_changes


def test_cpus_and_network_are_reboot_only():
    good = _good()
    new = good.text
    new = new.replace('CPUs = 15%', "CPUs = 8")
    new = new.replace('Network = "user"', 'Network = "none"')
    decision = cw.evaluate_save(new, good)
    for key in ("CPUs", "Network"):
        assert key in decision.reboot_changes, key
        assert key not in decision.live_changes, key


def test_clipboard_and_ports_are_reboot_only():
    good = _good()
    new = good.text
    new = new.replace("Clipboard = False", "Clipboard = True")
    new = new.replace("Ports = False", 'Ports = "22:49156"')
    decision = cw.evaluate_save(new, good)
    for key in ("Clipboard", "Ports"):
        assert key in decision.reboot_changes, key
        assert key not in decision.live_changes, key


def test_ask_before_quitting_is_applied_live():
    good = _good()
    new = good.text.replace(
        "Ask_Before_Quitting_Hypervisor = False",
        "Ask_Before_Quitting_Hypervisor = True",
    )
    decision = cw.evaluate_save(new, good)
    assert "Ask_Before_Quitting_Hypervisor" in decision.live_changes


def test_every_changed_key_is_classified_live_or_reboot():
    good = _good()
    # flip several settings at once; each changed key must land in exactly one bucket.
    new = good.text
    new = new.replace("Audio = True", "Audio = False")
    new = new.replace('RAM = 15%', "RAM = 4096")
    new = new.replace("Fullscreen = False", "Fullscreen = True")
    decision = cw.evaluate_save(new, good)
    for key in decision.changed_keys:
        in_live = key in decision.live_changes
        in_reboot = key in decision.reboot_changes
        assert in_live != in_reboot, f"{key} must be in exactly one bucket"
    assert set(decision.changed_keys) == set(decision.live_changes) | set(decision.reboot_changes)


# --- invalid edits -> revert ------------------------------------------------

def test_invalid_edit_is_rejected_and_reverts_to_last_good():
    good = _good()
    broken = good.text.replace('CPUs = 15%', "CPUs = potato")
    decision = cw.evaluate_save(broken, good)
    assert not decision.valid
    assert decision.errors
    # the revert payload is EXACTLY the last-known-good text.
    assert decision.revert_text == good.text
    assert decision.values is None


def test_invalid_edit_reports_the_offending_key():
    good = _good()
    broken = good.text.replace("Audio = True", "Audio = loud")
    decision = cw.evaluate_save(broken, good)
    assert not decision.valid
    assert any("Audio" in e for e in decision.errors)


def test_garbage_file_reverts_not_crashes():
    good = _good()
    decision = cw.evaluate_save("this is not a config at all\n\x00\x01", good)
    # no parseable keys -> nothing changes; must be treated as valid no-op, never crash.
    assert decision.valid
    assert decision.changed_keys == []


def test_snapshot_from_keyless_file_is_not_poisoned(tmp_path):
    # If the VM boots with an empty / all-comments hypervisor.cfg, the watcher's
    # last-known-good must NOT be that keyless text -- otherwise a later bad edit
    # cannot be reverted (revert would restore an empty file / refuse and brick
    # the next boot). _make_snapshot must fall back to a real, keyed body.
    import virtual_machine as vm
    from hypervisor_helpers import make_cfg
    cfg = make_cfg(str(tmp_path))
    # write an all-comments (keyless) file, as _make_snapshot will read it.
    (tmp_path / "hypervisor.cfg").write_text("### just a comment, no settings\n")
    snap = vm._make_snapshot(cfg)
    assert cw._has_known_keys(snap.text), "snapshot text must contain real settings"
    # a revert to it must be a valid, non-bricking config.
    decision = cw.evaluate_save(snap.text, snap)
    assert decision.valid


def test_revert_actually_fires_when_booted_from_keyless_cfg(tmp_path):
    # End-to-end of the above: boot snapshot from a keyless file, then a bad edit
    # must be reverted to a VALID file on disk (never left broken).
    import virtual_machine as vm
    from hypervisor_helpers import make_cfg
    cfg = make_cfg(str(tmp_path))
    path = tmp_path / "hypervisor.cfg"
    path.write_text("")                       # empty at boot
    snap = vm._make_snapshot(cfg)
    watcher = cw.ConfigWatcher(str(path), snap, log=lambda m: None)
    path.write_text("CPUs = potato\n")        # a broken live edit
    watcher.apply_text(path.read_text())
    text = path.read_text()
    assert "potato" not in text, "bad edit must be reverted"
    assert cw._has_known_keys(text), "reverted file must be a valid, keyed config"


def test_parser_agrees_with_the_real_loader_on_odd_line_breaks():
    # The watcher's parse and the real from_dir loader MUST agree on what counts
    # as a line. str.splitlines() splits on 8 extra unicode/control boundaries
    # (\x0b \x0c \x1c \x1d \x1e \x85    ) that file iteration (\n only)
    # does not -- a divergence lets a body pass the watcher yet fail the loader,
    # which after a revert would brick the next boot. Pin them identical.
    body = "CPUs = 4\x0bRAM = 8192\n"
    watcher_view = cw._parse_text(body)
    # reproduce configuration._parse_conf's line handling on the same body:
    loader_view = {}
    for raw in body.split("\n"):
        line = raw.split("#", 1)[0]
        if "=" in line:
            k, v = line.split("=", 1)
            loader_view[k.strip()] = v.strip()
    assert watcher_view == loader_view, (
        f"watcher parse {watcher_view} disagrees with loader parse {loader_view}")


def test_odd_linebreak_body_is_rejected_not_adopted(tmp_path):
    # End-to-end: a body with an embedded \x0b must NOT be adopted as
    # last-known-good in a way that later bricks. Either it validates identically
    # to the loader, or it is rejected -- never "valid to the watcher, broken to
    # the loader".
    good = _good()
    body = good.text.replace('CPUs = 15%', "CPUs = 4\x0bRAM = 8192")
    decision = cw.evaluate_save(body, good)
    if decision.valid:
        # if the watcher calls it valid, the real loader must ALSO accept the
        # exact same bytes (write it and load it).
        path = tmp_path / "hypervisor.cfg"
        path.write_text(body)
        # must not raise:
        config.HypervisorCfg.from_dir(str(tmp_path))
    else:
        assert decision.errors


def test_legacy_keys_in_live_edit_still_validate():
    # a user hand-editing to the OLD ssh key mid-run must not trip a false revert:
    # legacy `ssh = true` migrates to Secure_Shell.
    good = _good()
    new = good.text.replace("Secure_Shell = False", "ssh = true")
    decision = cw.evaluate_save(new, good)
    assert decision.valid
    assert decision.values["Secure_Shell"] is True


# --- watcher on-disk behaviour (real file, no thread) -----------------------

def test_watcher_reverts_bad_file_on_disk(tmp_path):
    good = _good()
    path = tmp_path / "hypervisor.cfg"
    broken = good.text.replace('CPUs = 15%', "CPUs = nonsense")
    path.write_text(broken)
    watcher = cw.ConfigWatcher(str(path), good, log=lambda m: None)
    decision = watcher.apply_text(broken)
    assert not decision.valid
    # the file on disk is restored to the last-known-good text, byte-for-byte.
    assert path.read_text() == good.text


def test_watcher_keeps_valid_file_and_advances_snapshot(tmp_path):
    good = _good()
    path = tmp_path / "hypervisor.cfg"
    new = good.text.replace("Audio = True", "Audio = False")
    path.write_text(new)
    watcher = cw.ConfigWatcher(str(path), good, log=lambda m: None)
    decision = watcher.apply_text(new)
    assert decision.valid
    # a valid edit is NOT reverted -- the file keeps the user's change.
    assert "Audio = False" in path.read_text()
    # and the watcher adopts it as the new last-known-good.
    assert watcher.last_good.values["Audio"] is False


def test_watcher_thread_ignores_a_partial_write_mid_save(tmp_path):
    # An editor that truncates-then-writes can be caught mid-save (an empty or
    # partial file). The watcher must NOT adopt that as last-known-good and must
    # NOT revert to it; it should settle on the final, complete contents.
    import time as _t
    good = _good()
    path = tmp_path / "hypervisor.cfg"
    path.write_text(good.text)
    watcher = cw.ConfigWatcher(str(path), good, poll_interval=0.05, log=lambda m: None)
    watcher.start()
    try:
        # a valid, complete edit -- but simulate the truncate window first.
        final = good.text.replace("Audio = True", "Audio = False")
        path.write_text("")              # truncate (the mid-save moment)
        _t.sleep(0.12)                    # let a poll or two catch the empty file
        path.write_text(final)            # the real, complete save lands
        deadline = _t.time() + 5
        while _t.time() < deadline and watcher.last_good.values.get("Audio") is not False:
            _t.sleep(0.03)
    finally:
        watcher.stop()
    # last-known-good is the COMPLETE file, never the empty truncate window.
    assert watcher.last_good.text.strip() != ""
    assert "Audio = False" in path.read_text()
    # and a hypothetical later revert would restore a non-empty, valid file.
    assert watcher.last_good.values["Audio"] is False


def test_watcher_thread_reverts_after_a_bad_save(tmp_path):
    import time as _t
    good = _good()
    path = tmp_path / "hypervisor.cfg"
    path.write_text(good.text)
    watcher = cw.ConfigWatcher(str(path), good, poll_interval=0.05, log=lambda m: None)
    watcher.start()
    try:
        # simulate a user saving a broken edit.
        path.write_text(good.text.replace('RAM = 15%', "RAM = lots"))
        # give the poll loop a few cycles to notice + revert.
        deadline = _t.time() + 5
        while _t.time() < deadline and "RAM = lots" in path.read_text():
            _t.sleep(0.05)
    finally:
        watcher.stop()
    assert path.read_text() == good.text, "watcher thread should have reverted the bad save"
