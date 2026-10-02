"""graphics.py - DRM render-node selection for sharing the host GPU with the guest.

When share_host_gpu is on, the guest's OpenGL (VirGL) is rendered on a host GPU
via a DRM render node; the finished frames then go out over SPICE. This is a
SHARED GPU (the host screen keeps working), NOT passthrough. WHICH physical GPU
renders is chosen entirely by the render node we pick here. Detection is
driver-based via sysfs (portable) rather than hardwired PCI paths, and NEVER
raises -- if nothing usable is found it returns None and virtual_machine.py degrades to a
generic software-rendered GPU.
"""

from __future__ import annotations

import glob
import os


def _node_driver(dev: str) -> str:
    """Driver name backing a /dev/dri/renderD* node, or '' if unknown."""
    name = os.path.basename(dev)
    link = f"/sys/class/drm/{name}/device/driver"
    try:
        return os.path.basename(os.path.realpath(link))
    except OSError:
        return ""


def select_render_node() -> str | None:
    """Return the best host DRM render node to offload guest GL onto, or None.

    Prefers a real GPU (nvidia / i915 / xe / amdgpu / radeon) over anything
    else, then falls back to any readable node. Returns None when no usable
    render node exists, which makes virtual_machine.py fall back to software rendering.
    """
    gpu_node = any_node = None
    for dev in sorted(glob.glob("/dev/dri/renderD*")):
        if not os.path.exists(dev) or not os.access(dev, os.R_OK):
            continue
        if any_node is None:
            any_node = dev
        if _node_driver(dev) in ("nvidia", "i915", "xe", "amdgpu", "radeon"):
            gpu_node = gpu_node or dev
    return gpu_node or any_node
