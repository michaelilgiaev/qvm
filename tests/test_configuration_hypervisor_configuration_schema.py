"""configuration_schema -- the typed hypervisor.cfg schema, coercion, and validation.

hypervisor.cfg is a real typed config: each key has a type (bool, string, int-or-percent,
Ports maps, false-or-path, list-of-paths) and a validator. This schema is the SINGLE
SOURCE OF TRUTH: HypervisorCfg.from_dir uses it to parse the file, and the live-reload
watcher uses the SAME validator to decide "valid -> apply" vs "invalid -> revert". So it
must be pure and airtight.

`coerce_all(raw: dict[str,str]) -> (values: dict, errors: list[str])`:
  * raw is the KEY=VALUE string map straight from the file (unknown keys ignored).
  * keys resolve CASE-INSENSITIVELY to their canonical Title_Case name; every key in the
    returned `values` dict is the canonical name.
  * on success every key is coerced to its Python type; errors is empty.
  * on ANY bad value the key's error is collected; a caller treats a non-empty errors
    list as "invalid format -> revert".
"""

from __future__ import annotations

import pytest

import configuration_schema as cs
from configuration_schema import Percent


# --- booleans (True/False, plus legacy spellings) ---------------------------

@pytest.mark.parametrize("raw,expected", [
    ("True", True), ("False", False),
    ("true", True), ("FALSE", False), ("  True  ", True),
    ("on", True), ("off", False), ("1", True), ("0", False), ("yes", True), ("no", False),
])
def test_bool_accepts_true_false_and_legacy(raw, expected):
    vals, errors = cs.coerce_all({"Secure_Shell": raw})
    assert not errors
    assert vals["Secure_Shell"] is expected


@pytest.mark.parametrize("bad", ["maybe", "tru", "", "2"])
def test_bool_rejects_non_boolean(bad):
    vals, errors = cs.coerce_all({"Secure_Shell": bad})
    assert errors, f"{bad!r} should be rejected as a bool"


def test_keys_are_case_insensitive():
    # secure_shell / SECURE_SHELL / Secure_Shell all resolve to the canonical key, and
    # legacy lowercase names (share_host_gpu) do too.
    for key in ("secure_shell", "SECURE_SHELL", "Secure_Shell"):
        vals, errors = cs.coerce_all({key: "True"})
        assert not errors and vals["Secure_Shell"] is True
    vals, errors = cs.coerce_all({"share_host_gpu": "False"})
    assert not errors and vals["Share_Host_GPU"] is False


# --- int-or-percent (RAM / CPUs / Disk_Size_GB) -----------------------------

def test_plain_numbers_coerce_to_int():
    vals, errors = cs.coerce_all({"RAM": "8192", "CPUs": "4", "Disk_Size_GB": "200"})
    assert not errors
    assert vals["RAM"] == 8192 and isinstance(vals["RAM"], int)
    assert vals["CPUs"] == 4
    assert vals["Disk_Size_GB"] == 200


@pytest.mark.parametrize("raw,pct", [("15%", 15), ('"15%"', 15), ("  100 %", 100), ("1%", 1)])
def test_percentages_coerce_to_percent(raw, pct):
    vals, errors = cs.coerce_all({"RAM": raw})
    assert not errors
    assert vals["RAM"] == Percent(pct)


@pytest.mark.parametrize("bad", ["0%", "101%", "200%"])
def test_percentage_out_of_range_rejected(bad):
    _, errors = cs.coerce_all({"CPUs": bad})
    assert errors, f"{bad!r} must be rejected (1..100 only)"


@pytest.mark.parametrize("bad", ["lots", "8g", "", "-4", "0", "3.5"])
def test_int_or_percent_rejects_garbage(bad):
    vals, errors = cs.coerce_all({"CPUs": bad})
    assert errors, f"CPUs={bad!r} should be rejected"


@pytest.mark.parametrize("bad", ["²", "³", "¹²", "٠١", "⁵"])
def test_rejects_unicode_digits_without_crashing(bad):
    # str.isdigit() is True for superscripts/other-script digits that int() cannot parse.
    # coerce_all must REJECT them cleanly, never raise ValueError.
    vals, errors = cs.coerce_all({"CPUs": bad})
    assert errors, f"CPUs={bad!r} must be rejected, not crash"


def test_coerce_all_tolerates_non_string_values():
    # defensive: coerce_all must never raise on a non-str value (e.g. a caller
    # passing an already-typed dict); it should treat it as invalid, not crash.
    _, errors = cs.coerce_all({"RAM": None})
    assert errors
    _, errors = cs.coerce_all({"CPUs": 5})       # already an int
    assert isinstance(errors, list)


# --- Ports (guest:host maps; the 22:host map is the ssh forward) -------------

def test_ports_single_map():
    vals, errors = cs.coerce_all({"Ports": "22:49156"})
    assert not errors and vals["Ports"] == [(22, 49156)]


def test_ports_many_maps_space_or_comma():
    space = cs.coerce_all({"Ports": "22:49156 1500:49157"})[0]
    comma = cs.coerce_all({"Ports": '"22:49156, 1500:49157"'})[0]
    assert space["Ports"] == [(22, 49156), (1500, 49157)]
    assert comma["Ports"] == [(22, 49156), (1500, 49157)]


def test_ports_false_is_empty():
    for raw in ("False", "", "false"):
        vals, errors = cs.coerce_all({"Ports": raw})
        assert not errors and vals["Ports"] == []


def test_ports_legacy_bare_number_is_the_ssh_map():
    # A bare number is the old ssh_guest_to_host_port_forward value -> guest 22 -> that host
    # port, so a legacy/codelis-written cfg still forwards :22.
    vals, errors = cs.coerce_all({"Ports": "49156"})
    assert not errors and vals["Ports"] == [(22, 49156)]


@pytest.mark.parametrize("bad", ["22:70000", "70000:22", "22:", ":49156", "a:b", "22:49156:1"])
def test_ports_rejects_bad_maps(bad):
    _, errors = cs.coerce_all({"Ports": bad})
    assert errors, f"Ports={bad!r} should be rejected"


def test_ports_rejects_duplicate_guest():
    _, errors = cs.coerce_all({"Ports": "22:49156, 22:49157"})
    assert errors, "duplicate guest port must be rejected"


# --- audio (now a bool; legacy on/off still parses) -------------------------

@pytest.mark.parametrize("raw,expected", [("True", True), ("False", False),
                                          ("on", True), ("off", False)])
def test_audio_is_bool(raw, expected):
    vals, errors = cs.coerce_all({"Audio": raw})
    assert not errors and vals["Audio"] is expected


def test_audio_rejects_other():
    vals, errors = cs.coerce_all({"Audio": "loud"})
    assert errors


# --- Shared: False OR True/"" (working dir) OR a path -----------------------

def test_shared_false_is_bool_false():
    vals, errors = cs.coerce_all({"Shared": "False"})
    assert not errors and vals["Shared"] is False


def test_shared_empty_means_working_dir_sentinel():
    vals, errors = cs.coerce_all({"Shared": ""})
    assert not errors and vals["Shared"] is True


def test_shared_path_is_kept_as_string():
    vals, errors = cs.coerce_all({"Shared": '"/mnt/host/share"'})
    assert not errors and vals["Shared"] == "/mnt/host/share"


def test_shared_true_means_working_dir():
    vals, errors = cs.coerce_all({"Shared": "True"})
    assert not errors and vals["Shared"] is True


# --- Network: user | none | <interface> (quotes optional) -------------------

@pytest.mark.parametrize("good", ["user", "none", '"user"', "'none'"])
def test_network_keywords(good):
    vals, errors = cs.coerce_all({"Network": good})
    assert not errors and vals["Network"] in ("user", "none")


def test_network_interface_name_kept():
    vals, errors = cs.coerce_all({"Network": '"eno1"'})
    assert not errors and vals["Network"] == "eno1"


@pytest.mark.parametrize("bad", ["", "eth 0", "bad/iface", "a b c"])
def test_network_rejects_garbage(bad):
    vals, errors = cs.coerce_all({"Network": bad})
    assert errors, f"Network={bad!r} should be rejected"


# --- USB: False | one path | many paths -------------------------------------

def test_usb_false_is_empty_list():
    vals, errors = cs.coerce_all({"USB": "False"})
    assert not errors and vals["USB"] == []


def test_usb_single_path_is_one_element_list():
    vals, errors = cs.coerce_all({"USB": '"/dev/bus/usb/003/004"'})
    assert not errors and vals["USB"] == ["/dev/bus/usb/003/004"]


def test_usb_many_paths_space_or_comma_separated():
    space = cs.coerce_all({"USB": "/dev/bus/usb/003/004 /dev/sdb"})[0]
    comma = cs.coerce_all({"USB": "/dev/bus/usb/003/004, /dev/sdb"})[0]
    assert space["USB"] == ["/dev/bus/usb/003/004", "/dev/sdb"]
    assert comma["USB"] == ["/dev/bus/usb/003/004", "/dev/sdb"]


def test_usb_rejects_relative_or_nonpath_tokens():
    vals, errors = cs.coerce_all({"USB": "not-a-path"})
    assert errors, "a non-absolute usb token should be rejected"


def test_usb_legacy_boolean_is_tolerated_as_no_passthrough():
    # Old cfgs wrote `usb = false`/`true`. Treat legacy booleans as "no device
    # passthrough" ([]) so a pre-redesign hypervisor.cfg still loads.
    assert cs.coerce_all({"USB": "false"}) == ({"USB": []}, [])
    assert cs.coerce_all({"USB": "true"}) == ({"USB": []}, [])


# --- whole-file behaviour ---------------------------------------------------

def test_unknown_keys_are_ignored_not_errors():
    vals, errors = cs.coerce_all({"totally_made_up": "1", "RAM": "2048"})
    assert not errors
    assert "totally_made_up" not in vals
    assert vals["RAM"] == 2048


def test_multiple_errors_all_collected():
    vals, errors = cs.coerce_all({"CPUs": "lots", "Audio": "loud", "Secure_Shell": "maybe"})
    assert len(errors) >= 3


def test_defaults_round_trip_clean():
    # Every default value, rendered to text and reparsed, must validate.
    import configuration as config
    raw = config.parse_conf_text(config._hypervisor_cfg_text(config._render_defaults()))
    vals, errors = cs.coerce_all(raw)
    assert not errors, f"generated default cfg must validate, got: {errors}"
