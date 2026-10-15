"""CPU% from one instant stats sample, and the control routes waking the
snapshot worker. Docker is stubbed at import, like the other route tests."""

import sys
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main


def sample(container_ns, host_ns, cpus=4):
    """What Docker returns for one_shot=True: no previous reading."""
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": container_ns},
            "system_cpu_usage": host_ns,
            "online_cpus": cpus,
        },
        "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
        "memory_stats": {"usage": 100, "limit": 1000, "stats": {}},
    }


@pytest.fixture(autouse=True)
def _clean():
    main.previous_cpu.clear()
    yield
    main.previous_cpu.clear()


def cpu_percent(container_id, stats):
    main.use_previous_cpu(container_id, stats)
    return main.calculate_cpu_percent(stats)


def test_the_first_sight_of_a_container_reads_zero_not_the_average_since_boot():
    assert cpu_percent("a", sample(5_000_000_000, 90_000_000_000_000)) == 0.0


def test_cpu_is_the_change_since_the_last_snapshot():
    cpu_percent("a", sample(1_000_000_000, 100_000_000_000))
    # 0.5 s of CPU while the host's 4 CPUs ran for 2 s (8 s of CPU time).
    assert cpu_percent("a", sample(1_500_000_000, 108_000_000_000)) == pytest.approx(25.0)


def test_containers_do_not_share_a_previous_reading():
    cpu_percent("a", sample(1_000_000_000, 100_000_000_000))
    assert cpu_percent("b", sample(9_000_000_000, 100_000_000_000)) == 0.0


def test_a_restarted_container_whose_counters_went_back_reads_zero():
    cpu_percent("a", sample(9_000_000_000, 100_000_000_000))
    assert cpu_percent("a", sample(1_000_000_000, 108_000_000_000)) == 0.0


def test_container_stats_take_a_single_instant_sample():
    container = mock.MagicMock()
    container.status = "running"
    container.id = "abc"
    container.stats.return_value = sample(1, 1)
    main.get_container_stats(container)
    container.stats.assert_called_once_with(stream=False, one_shot=True)


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_a_control_action_wakes_the_snapshot_worker(action):
    container = mock.MagicMock()
    container.name = "jellyfin"
    main.cache_wake.clear()
    with mock.patch.object(main, "get_container_or_404", return_value=container):
        result = TestClient(main.app).post(f"/containers/abc/{action}")
    assert result.json()["success"] is True
    assert main.cache_wake.is_set()
    main.cache_wake.clear()
