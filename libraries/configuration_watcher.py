"""configuration_watcher.py - live hypervisor.cfg reload with validation and safe revert.

While a VM runs, the hypervisor watches hypervisor.cfg (mtime poll on a daemon
thread, matching virtual_machine._maximize_window; stdlib only, no new deps). On
every save there are exactly two outcomes:

  1. VALID   -> the new values are applied; changed keys are split into those
                applied LIVE (viewer-side toggles) and those that only take
                effect on the next boot (device topology: RAM, CPUs, Network,
                USB, Shared, Ports, Clipboard, Disk_Size_GB, Audio).
  2. INVALID -> the file is reverted to the LAST-KNOWN-GOOD contents, so a broken
                edit never bricks the VM.

The accept/revert decision is the PURE function evaluate_save(); it does no I/O
and is fully unit-tested. ConfigWatcher is the thin thread that reads the file,
calls evaluate_save(), and either writes the revert or logs+applies the diff.

WHY so few keys apply live: RAM/CPUs/-m/-smp, the netdev/NIC (Network, Ports), the
virtiofs share, the clipboard channel and USB host devices are fixed at QEMU launch and
cannot be re-plugged safely from a config poke; changing them needs a fresh boot. The
viewer-side flags (Fullscreen / Ask_Before_Quitting_Hypervisor) are host/viewer concerns
rather than guest device topology, so they are treated as live (they re-read on the next
viewer action / relaunch); everything else is reboot-required and clearly logged as such.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field

# Flat sibling imports: the modules live directly in libraries/ (no package).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import configuration_schema  # noqa: E402  (after the sys.path bootstrap above)
import configuration  # noqa: E402


# Keys whose change we surface as "applied live" vs "needs a reboot". Anything
# not listed as live is reboot-required (safe default: never claim a device
# topology change took effect when it did not).
_LIVE_KEYS = frozenset({"Fullscreen", "Ask_Before_Quitting_Hypervisor"})


@dataclass
class Snapshot:
    """The last-known-good config: coerced values + the exact file text to
    restore on a bad edit."""
    values: dict
    text: str


@dataclass
class ChangeDecision:
    valid: bool
    values: "dict | None" = None          # coerced new values (valid only)
    errors: list = field(default_factory=list)
    revert_text: "str | None" = None      # last-good text to restore (invalid only)
    changed_keys: list = field(default_factory=list)
    live_changes: list = field(default_factory=list)
    reboot_changes: list = field(default_factory=list)


def evaluate_save(new_text: str, last_good: Snapshot) -> ChangeDecision:
    """PURE. Decide what to do with a freshly-saved hypervisor.cfg body.

    Parses+validates new_text against the schema (honouring the same legacy-key
    migration as a normal load). On any invalid value, returns valid=False with
    the errors and the last-known-good text to restore. On success, returns the
    new coerced values plus the changed keys partitioned into live vs
    reboot-required.
    """
    raw = configuration._migrate_legacy_keys(_parse_text(new_text))
    coerced, errors = configuration_schema.coerce_all(raw)
    if errors:
        return ChangeDecision(valid=False, errors=errors, revert_text=last_good.text)

    # Layer the parsed values over the last-good values (absent keys keep their
    # current value, exactly like from_dir layers over the defaults).
    new_values = dict(last_good.values)
    new_values.update(coerced)

    changed = [k for k in configuration_schema.KEYS
               if new_values.get(k) != last_good.values.get(k)]
    live = [k for k in changed if k in _LIVE_KEYS]
    reboot = [k for k in changed if k not in _LIVE_KEYS]
    return ChangeDecision(
        valid=True, values=new_values,
        changed_keys=changed, live_changes=live, reboot_changes=reboot,
    )


def _parse_text(text: str) -> dict:
    """KEY=VALUE parse of an in-memory cfg body. Delegates to the ONE canonical
    parser in configuration so the watcher's view can never disagree with the
    real loader (a divergence would let a body validate here yet mis-parse at the
    next boot, which -- after a revert to it -- would brick the VM)."""
    return configuration.parse_conf_text(text)


def _has_known_keys(text: str) -> bool:
    """True if the body defines at least one recognized (or legacy) setting. Guards
    against adopting an empty / all-comments / partial-write body as the last-known-good.
    Case-insensitive (via canonical_key), so a hand-typed `cpus = ...` counts the same as
    `CPUs = ...`."""
    raw = configuration._migrate_legacy_keys(_parse_text(text))
    return any(configuration_schema.canonical_key(k) is not None for k in raw)


def _atomic_write(path: str, text: str) -> None:
    """Write text to path atomically (temp file + os.replace), so a concurrent
    reader -- including our own poll loop -- never observes a half-written revert."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".hypervisor.cfg.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class ConfigWatcher:
    """Background mtime-poll watcher over one hypervisor.cfg.

    start() spawns a daemon thread; stop() ends it. Each detected change runs
    evaluate_save(): a valid edit updates the in-memory last-known-good and logs
    live/reboot changes; an invalid edit rewrites the file with the last-good
    text (safe revert). All logging goes to stderr, matching the rest of do_run.
    """

    def __init__(self, path: str, last_good: Snapshot, *,
                 poll_interval: float = 1.0, log=None):
        self.path = path
        self.last_good = last_good
        self.poll_interval = poll_interval
        self._log = log or (lambda m: print(m, file=sys.stderr))
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None
        # Change detection is CONTENT-based, not mtime-based: two fast saves can
        # share one mtime tick (the fs mtime granularity race), which an
        # mtime-only poll silently misses. The file is tiny, so re-reading it
        # each poll is cheap and immune to that race. Seed with what's on disk.
        self._last_seen = self._read()
        # Debounce: a change is acted on only once its content is STABLE across
        # two consecutive polls. That skips the truncate/partial-write window of
        # a non-atomic editor save (which could otherwise be adopted as
        # last-known-good and later reverted TO -- restoring an empty file).
        self._pending: "str | None" = None

    def _read(self) -> "str | None":
        try:
            with open(self.path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.poll_interval)
            text = self._read()
            if text is None or text == self._last_seen:
                self._pending = None      # settled / vanished -> nothing pending
                continue
            if text != self._pending:
                # first sighting of this content -- wait one more poll to confirm
                # it is a complete, settled save and not a mid-write snapshot.
                self._pending = text
                continue
            # seen twice unchanged -> stable. A keyless body (empty / partial /
            # all-comments) is never acted on: don't advance _last_seen to it, so
            # the eventual complete save is still detected as a change.
            if not _has_known_keys(text):
                self._pending = None
                continue
            self._pending = None
            self._last_seen = text
            self.apply_text(text)

    def apply_text(self, text: str) -> ChangeDecision:
        """Evaluate a new cfg body and act on it. Returns the decision (also
        used directly by tests to drive the watcher without touching the disk).

        `text` is what is now on disk; on a valid change it becomes the new
        last-known-good VERBATIM (comments/formatting preserved), so a later
        revert restores the user's real file, not a canonical rerender."""
        # keep _last_seen honest for callers that invoke apply_text directly
        # (the thread already sets it before calling us; setting again is a no-op).
        self._last_seen = text
        decision = evaluate_save(text, self.last_good)
        if not decision.valid:
            self._revert(decision.errors)
            return decision
        # Never adopt a keyless body (empty / all-comments / garbage) as the new
        # last-known-good: it is not a state worth reverting TO, and could be a
        # partial write that slipped past the debounce. Leave last_good intact.
        if not _has_known_keys(text):
            return decision
        if not decision.changed_keys:
            # a real, complete no-op edit (e.g. a comment tweak) refreshes the
            # baseline text so a later revert keeps the user's latest formatting.
            self.last_good = Snapshot(values=self.last_good.values, text=text)
            return decision
        self._apply(decision, text)
        return decision

    def _revert(self, errors: list) -> None:
        # Safety net: refuse to overwrite with a poisoned (empty/keyless)
        # baseline. last_good is only ever advanced through the keyless guard in
        # apply_text, so this should never trip -- but a destructive write of an
        # empty file is exactly the failure this whole feature exists to prevent.
        if not _has_known_keys(self.last_good.text):
            self._log("hypervisor.cfg: invalid edit, but last-known-good is "
                      "unavailable -- leaving the file as-is:")
            for e in errors:
                self._log(f"  - {e}")
            return
        self._log("hypervisor.cfg: invalid edit -- reverting to last-known-good:")
        for e in errors:
            self._log(f"  - {e}")
        try:
            _atomic_write(self.path, self.last_good.text)
            # adopt our own write so the next poll does not re-trigger on it.
            self._last_seen = self.last_good.text
        except OSError as exc:
            self._log(f"hypervisor.cfg: could not restore last-known-good: {exc}")

    def _apply(self, decision: ChangeDecision, text: str) -> None:
        if decision.live_changes:
            self._log("hypervisor.cfg: applied live: "
                      + ", ".join(sorted(decision.live_changes)))
        if decision.reboot_changes:
            self._log("hypervisor.cfg: takes effect on next boot: "
                      + ", ".join(sorted(decision.reboot_changes)))
        # adopt the new values AND the user's verbatim file as the last-known-good.
        self.last_good = Snapshot(values=decision.values, text=text)
