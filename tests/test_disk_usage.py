import os

import pytest

import disk_usage
from disk_usage import DiskUsageError


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_ROOT", str(tmp_path))
    disk_usage.forget()
    yield tmp_path
    disk_usage.forget()


def write(path, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size))


def by_name(view):
    return {e["name"]: e for e in view["entries"]}


def test_sums_folders_and_sorts_biggest_first(host):
    write(host / "data" / "big" / "a.bin", 400_000)
    write(host / "data" / "big" / "deep" / "b.bin", 300_000)
    write(host / "data" / "small" / "c.bin", 10_000)
    write(host / "data" / "loose.bin", 50_000)

    view = disk_usage.usage("/data", wait=True)

    assert view["state"] == "done"
    assert view["parent"] == "/"
    names = [e["name"] for e in view["entries"]]
    assert names[0] == "big"
    rows = by_name(view)
    assert rows["big"]["kind"] == "dir" and rows["big"]["files"] == 2
    assert rows["big"]["bytes"] >= 700_000
    assert rows["loose.bin"]["kind"] == "file"
    assert rows["small"]["bytes"] < rows["loose.bin"]["bytes"] + 20_000
    assert view["total_bytes"] == sum(e["bytes"] for e in view["entries"])


def test_hard_links_count_once(host):
    write(host / "d" / "x" / "one.bin", 200_000)
    os.makedirs(host / "d" / "y")
    os.link(host / "d" / "x" / "one.bin", host / "d" / "y" / "same.bin")

    view = disk_usage.usage("/d", wait=True)
    rows = by_name(view)
    counted = rows["x"]["bytes"] + rows["y"]["bytes"]
    assert counted < 2 * 200_000


def test_symlinks_are_listed_not_followed(host):
    write(host / "real" / "f.bin", 100_000)
    os.makedirs(host / "top")
    os.symlink(host / "real", host / "top" / "link")

    rows = by_name(disk_usage.usage("/top", wait=True))
    assert rows["link"]["kind"] == "link"
    assert rows["link"]["bytes"] == 0


def test_refuses_bad_paths(host):
    with pytest.raises(DiskUsageError):
        disk_usage.usage("relative")
    with pytest.raises(DiskUsageError):
        disk_usage.usage("/a/../etc")

    missing = disk_usage.usage("/nope", wait=True)
    assert missing["state"] == "error" and "doesn't exist" in missing["error"]

    write(host / "file.bin", 10)
    not_dir = disk_usage.usage("/file.bin", wait=True)
    assert not_dir["state"] == "error"


def test_cached_until_refresh(host):
    write(host / "c" / "a.bin", 1000)
    first = disk_usage.usage("/c", wait=True)
    write(host / "c" / "b.bin", 1000)

    assert len(disk_usage.usage("/c", wait=True)["entries"]) == len(first["entries"])
    assert len(disk_usage.usage("/c", refresh=True, wait=True)["entries"]) == 2


def test_long_listings_are_trimmed(host, monkeypatch):
    monkeypatch.setattr(disk_usage, "MAX_ENTRIES", 3)
    for i in range(5):
        write(host / "many" / f"f{i}.bin", 1000 * (i + 1))

    view = disk_usage.usage("/many", wait=True)
    assert len(view["entries"]) == 3
    assert view["more"]["count"] == 2
