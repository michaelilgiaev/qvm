"""host_resources.py - read the host's total RAM / CPU / disk, and resolve "N%" sizes.

The redesigned hypervisor.cfg lets RAM, CPUs and Disk_Size_GB be written either as a
plain number OR as a percentage of the host machine ("15%"). Turning a percentage into
a concrete number needs the host totals, so this is the ONE place that reads them:

  * host_total_ram_mib()  -- total RAM in MiB, from /proc/meminfo (MemTotal).
  * host_cpu_count()      -- logical CPU count (os.cpu_count()).
  * host_total_disk_gb(path) -- total size of the filesystem holding `path`, in GiB.

Everything degrades to a sane fallback rather than raising, so a VM launch never fails
just because a host probe came back empty (a container with no /proc/meminfo, a locked-
down os.cpu_count, ...). The percentage resolvers clamp to a floor of 1 so "1%" of a
tiny host can never yield 0 RAM / 0 vCPUs / a 0G disk (all of which QEMU rejects).

PURE-ish: the only impurity is reading the host (a file + two stdlib calls), factored
here so the schema coercers that call resolve_percent stay unit-testable by
monkeypatching these functions.
"""

from __future__ import annotations

import math
import os
import shutil

# Fallbacks used only when a host probe comes back unusable. Deliberately modest so a
# percentage of the fallback is still a workable VM (not, say, half a terabyte of RAM).
_FALLBACK_RAM_MIB = 4096
_FALLBACK_CPUS = 4
_FALLBACK_DISK_GB = 64


def host_total_ram_mib() -> int:
    """Total host RAM in MiB, parsed from /proc/meminfo's MemTotal (which is in kiB).
    Falls back to _FALLBACK_RAM_MIB if the file is missing or unparseable."""
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    # "MemTotal:       16307412 kB"
                    kib = int(line.split()[1])
                    return max(1, kib // 1024)
    except (OSError, ValueError, IndexError):
        pass
    return _FALLBACK_RAM_MIB


def host_cpu_count() -> int:
    """Logical CPU count (os.cpu_count()), or _FALLBACK_CPUS when it is unavailable."""
    n = os.cpu_count()
    return n if n and n > 0 else _FALLBACK_CPUS


def host_total_disk_gb(path: str) -> int:
    """Total size (GiB) of the filesystem that `path` lives on. Walks up to the nearest
    existing ancestor so a not-yet-created VM dir still resolves (the disk lands on the
    parent's filesystem). Falls back to _FALLBACK_DISK_GB when the probe fails."""
    probe = path or "."
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe.rstrip("/")) or "/"
        if parent == probe:
            break
        probe = parent
    try:
        total = shutil.disk_usage(probe or "/").total
        return max(1, total // (1024 ** 3))
    except OSError:
        return _FALLBACK_DISK_GB


def resolve_percent(percent: int, total: int) -> int:
    """`percent`% of `total`, rounded to the nearest whole unit and floored at 1.

    Rounding (not truncation) so 15% of 16 vCPUs is 2 (2.4 -> 2) rather than a
    surprise, and the floor guarantees a positive result for any 1..100 percent of any
    total >= 1 (QEMU rejects 0 RAM / 0 cpus / a 0G disk)."""
    return max(1, int(math.floor(total * percent / 100 + 0.5)))
