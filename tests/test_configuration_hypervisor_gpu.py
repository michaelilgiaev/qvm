"""gpu.select_render_node -- which host DRM render node the guest's GL is
offloaded onto when share_host_gpu is on.

The contract: prefer a real GPU node (nvidia / i915 / xe / amdgpu / radeon),
otherwise fall back to any readable node, otherwise None (which makes virtual_machine.py drop
to a generic software-rendered GPU). We inject a fake /dev/dri topology by
patching the glob + the per-node driver probe, so the test runs on any host
regardless of its real GPUs.
"""

from __future__ import annotations

import pytest

import graphics as gpu


@pytest.fixture
def fake_dri(monkeypatch):
    """Install a fake set of render nodes with chosen drivers.

    Usage: fake_dri({"/dev/dri/renderD128": "i915", "/dev/dri/renderD129": "nvidia"}).
    All nodes are treated as existing and readable.
    """
    def _install(nodes: dict[str, str]):
        paths = sorted(nodes)
        monkeypatch.setattr(gpu.glob, "glob", lambda pat: list(paths))
        monkeypatch.setattr(gpu.os.path, "exists", lambda p: p in nodes)
        monkeypatch.setattr(gpu.os, "access", lambda p, mode: p in nodes)
        monkeypatch.setattr(gpu, "_node_driver", lambda dev: nodes.get(dev, ""))
    return _install


def test_prefers_a_real_gpu_over_a_non_gpu_node(fake_dri):
    # A "mystery" node sorts first but the nvidia node is the real GPU -> nvidia.
    fake_dri({"/dev/dri/renderD128": "mystery", "/dev/dri/renderD129": "nvidia"})
    assert gpu.select_render_node() == "/dev/dri/renderD129"


def test_any_real_gpu_family_is_accepted(fake_dri):
    fake_dri({"/dev/dri/renderD128": "amdgpu"})
    assert gpu.select_render_node() == "/dev/dri/renderD128"
    fake_dri({"/dev/dri/renderD128": "i915"})
    assert gpu.select_render_node() == "/dev/dri/renderD128"


def test_first_real_gpu_wins_when_several(fake_dri):
    fake_dri({"/dev/dri/renderD128": "i915", "/dev/dri/renderD129": "nvidia"})
    # Both are real GPUs; the lower-numbered node is picked (sorted order).
    assert gpu.select_render_node() == "/dev/dri/renderD128"


def test_unknown_driver_still_usable_as_any_node(fake_dri):
    # No recognized GPU driver -> the node is still returned as last-resort "any".
    fake_dri({"/dev/dri/renderD128": "mystery"})
    assert gpu.select_render_node() == "/dev/dri/renderD128"


def test_no_nodes_returns_none(fake_dri):
    fake_dri({})
    assert gpu.select_render_node() is None
