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
    for cache in (main.previous_cpu, main.image_info_cache, main.size_cache):
        cache.clear()
    yield
    for cache in (main.previous_cpu, main.image_info_cache, main.size_cache):
        cache.clear()


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


def a_container(image_tags=("jellyfin/jellyfin:latest",), image_error=None):
    container = mock.MagicMock()
    container.id = "c1"
    container.name = "jellyfin"
    container.attrs = {"Image": "sha256:aaa", "Config": {"Image": "jellyfin/jellyfin"}}
    if image_error:
        type(container).image = mock.PropertyMock(side_effect=image_error)
    else:
        container.image.tags = list(image_tags)
        container.image.short_id = "sha256:aaa"
        container.image.attrs = {"Size": 700}
    return container


def test_an_image_is_inspected_once_however_many_snapshots_ask():
    container = a_container()
    inspected = mock.PropertyMock(return_value=container.image)
    type(container).image = inspected
    for _ in range(5):
        assert main.image_name(container) == "jellyfin/jellyfin:latest"
    assert inspected.call_count == 1


def test_a_container_whose_image_was_deleted_is_still_listed_by_its_config_name():
    container = a_container(image_error=RuntimeError("No such image"))
    assert main.image_name(container) == "jellyfin/jellyfin"
    assert main.image_info(container)["size"] == 0


def test_disk_use_is_asked_for_once_per_ttl_and_the_image_size_rides_along():
    container = a_container()
    answer = {"SizeRw": 5, "SizeRootFs": 900}
    with mock.patch.object(main, "client") as docker_client:
        docker_client.api._result.return_value = answer
        first = main.get_container_size(container)
        second = main.get_container_size(container)
    assert first == second == {"writable_bytes": 5, "rootfs_bytes": 900, "image_bytes": 700}
    assert docker_client.api._get.call_count == 1


def test_a_failed_size_query_is_retried_next_time_not_cached():
    container = a_container()
    with mock.patch.object(main, "client") as docker_client:
        docker_client.api._get.side_effect = RuntimeError("busy")
        assert main.get_container_size(container)["writable_bytes"] == 0
        docker_client.api._get.side_effect = None
        docker_client.api._result.return_value = {"SizeRw": 7, "SizeRootFs": 8}
        assert main.get_container_size(container)["writable_bytes"] == 7
