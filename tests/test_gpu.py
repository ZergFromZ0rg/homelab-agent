"""GPU reporting: which source sees what, and saying so when the runtime
is missing rather than quietly reporting half a card."""

import sys
from unittest import mock

import pytest

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main


def nvidia_card(name="NVIDIA GeForce GTX 1650 SUPER"):
    return {
        "vendor": "nvidia", "name": name, "utilization_percent": 12.0,
        "memory_used_mb": 512.0, "memory_total_mb": 4096.0,
        "temperature_c": 41.0, "power_draw_w": 22.0,
        "power_limit_w": 100.0, "fan_percent": 26.0,
    }


def drm_card(vendor="amd", name=None):
    return {
        "vendor": vendor, "name": name or f"{vendor.upper()} GPU 1002:1636",
        "device_id": "0x1636", "utilization_percent": None,
        "memory_used_mb": None, "memory_total_mb": None,
        "temperature_c": 44.0, "power_draw_w": None,
        "power_limit_w": None, "fan_percent": None,
    }


def sources(monkeypatch, nvidia=None, drm=None):
    monkeypatch.setattr(main, "get_nvidia_gpu_stats", lambda: nvidia)
    monkeypatch.setattr(main, "get_drm_gpu_stats", lambda: drm)


def test_no_gpu_at_all(monkeypatch):
    sources(monkeypatch)
    assert main.get_gpu_stats() == {"available": False, "count": 0, "devices": []}


def test_every_nvidia_card_is_reported(monkeypatch):
    """nvidia-smi lists one line per card, so SLI and multi-GPU come for
    free — this pins that they all survive."""
    sources(monkeypatch, nvidia=[nvidia_card("GPU A"), nvidia_card("GPU B")])

    stats = main.get_gpu_stats()

    assert stats["count"] == 2
    assert [g["name"] for g in stats["devices"]] == ["GPU A", "GPU B"]
    assert "hint" not in stats


def test_an_amd_card_needs_no_runtime(monkeypatch):
    """/sys/class/drm is mounted into every container by default."""
    sources(monkeypatch, drm=[drm_card("amd")])

    stats = main.get_gpu_stats()

    assert stats["available"] is True
    assert stats["devices"][0]["vendor"] == "amd"
    assert stats["devices"][0]["temperature_c"] == 44.0
    assert "hint" not in stats


def test_a_mixed_host_reports_both_cards(monkeypatch):
    """This used to report only the NVIDIA one: DRM was a fallback that
    never ran once nvidia-smi answered."""
    sources(monkeypatch, nvidia=[nvidia_card()], drm=[drm_card("amd")])

    stats = main.get_gpu_stats()

    assert stats["count"] == 2
    assert {g["vendor"] for g in stats["devices"]} == {"nvidia", "amd"}


def test_a_card_seen_by_both_sources_is_not_listed_twice(monkeypatch):
    sources(
        monkeypatch,
        nvidia=[nvidia_card()],
        drm=[drm_card("nvidia"), drm_card("amd")],
    )

    stats = main.get_gpu_stats()

    assert stats["count"] == 2
    assert [g["vendor"] for g in stats["devices"]] == ["nvidia", "amd"]
    # The full nvidia-smi reading survived, not the bare DRM one.
    assert stats["devices"][0]["utilization_percent"] == 12.0


def test_an_nvidia_card_without_the_runtime_says_so(monkeypatch):
    """The failure that went unnoticed for weeks: the card is detected, so
    it looks fine, but every number worth having is missing."""
    sources(monkeypatch, drm=[drm_card("nvidia", "NVIDIA GPU 10DE:2187")])

    stats = main.get_gpu_stats()

    assert stats["available"] is True
    assert stats["devices"][0]["runtime_missing"] is True
    assert "AGENT_RUNTIME=nvidia" in stats["hint"]


def test_no_hint_when_the_runtime_is_working(monkeypatch):
    sources(monkeypatch, nvidia=[nvidia_card()], drm=[drm_card("nvidia")])

    stats = main.get_gpu_stats()

    assert "hint" not in stats
    assert "runtime_missing" not in stats["devices"][0]


def test_an_amd_card_is_never_flagged_as_missing_a_runtime(monkeypatch):
    sources(monkeypatch, drm=[drm_card("amd"), drm_card("intel")])

    stats = main.get_gpu_stats()

    assert "hint" not in stats
    assert all("runtime_missing" not in g for g in stats["devices"])
