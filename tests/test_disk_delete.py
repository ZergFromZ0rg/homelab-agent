import os
import shutil

import pytest

import disk_delete
import disk_usage
from disk_usage import DiskUsageError


class FakeRunning:
    def __init__(self, name, sources):
        self.name = name
        self.attrs = {"Mounts": [{"Type": "bind", "Source": s} for s in sources]}


class FakeHelper:
    def __init__(self, code, on_wait):
        self.code = code
        self.on_wait = on_wait
        self.removed = False

    def wait(self, timeout=None):
        self.on_wait()
        return {"StatusCode": self.code}

    def logs(self):
        return b"rm: cannot remove: busy" if self.code else b""

    def remove(self, force=False):
        self.removed = True


class FakeClient:
    """Runs the 'helper' by deleting through HOST_ROOT, the way rm would."""

    def __init__(self, root, running=(), code=0):
        self.root = root
        self.calls = []
        self.helpers = []
        outer = self

        class Containers:
            def list(self):
                return list(running)

            def get(self, _):
                raise RuntimeError("not in a container")

            def run(self, image, command=None, volumes=None, **kwargs):
                outer.calls.append({"command": command, "volumes": volumes, **kwargs})
                (parent, spec), = volumes.items()
                target = command[-1].replace("/target", str(root) + parent, 1)

                def act():
                    if code == 0:
                        if os.path.isdir(target) and not os.path.islink(target):
                            shutil.rmtree(target)
                        else:
                            os.remove(target)

                helper = FakeHelper(code, act)
                outer.helpers.append(helper)
                return helper

        self.containers = Containers()


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "homelab-agent")
    disk_usage.forget()
    yield tmp_path
    disk_usage.forget()


def write(path, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_refuses_the_dangerous_ones(host):
    (host / "home").mkdir()
    (host / "etc" / "ssh").mkdir(parents=True)
    write(host / "var" / "lib" / "docker" / "x", 10)
    client = FakeClient(host)

    for path, reason in [
        ("/home", "top-level"),
        ("/etc/ssh", "operating system"),
        ("/var/lib/docker/x", "operating system"),
        ("/home/ghost", "doesn't exist"),
        ("/home/../etc", "'..'"),
        # A doubled leading slash still reaches /etc on disk; it used to
        # slip past the system-folder check, which compared strings.
        ("//etc/ssh", "operating system"),
        ("//home", "top-level"),
    ]:
        with pytest.raises(DiskUsageError, match=reason):
            disk_delete.check(client, path)
    assert client.calls == []


def test_refuses_a_folder_a_container_uses_but_allows_files_inside(host):
    write(host / "home" / "zerg" / "media" / "old.mkv", 1000)
    client = FakeClient(host, running=[FakeRunning("jellyfin", ["/home/zerg/media"])])

    with pytest.raises(DiskUsageError, match="jellyfin is using"):
        disk_delete.check(client, "/home/zerg/media")
    with pytest.raises(DiskUsageError, match="jellyfin is using"):
        disk_delete.check(client, "/home/zerg")  # contains the mount

    assert disk_delete.check(client, "/home/zerg/media/old.mkv")["kind"] == "file"


def test_deletes_through_a_helper_with_only_the_parent_writable(host):
    write(host / "home" / "zerg" / "clips" / "a" / "1.mp4", 50_000)
    write(host / "home" / "zerg" / "clips" / "b.mp4", 20_000)
    client = FakeClient(host)

    before = disk_usage.usage("/home/zerg/clips", wait=True)
    home_before = disk_usage.usage("/home/zerg", wait=True)
    clips_before = next(e["bytes"] for e in home_before["entries"] if e["name"] == "clips")
    size_a = next(e["bytes"] for e in before["entries"] if e["name"] == "a")

    result = disk_delete.delete(client, "/home/zerg/clips/a")

    call = client.calls[0]
    assert call["command"] == ["rm", "-rf", "--one-file-system", "--", "/target/a"]
    assert call["volumes"] == {"/home/zerg/clips": {"bind": "/target", "mode": "rw"}}
    assert call["network_disabled"] is True
    assert client.helpers[0].removed
    assert result == {"success": True, "path": "/home/zerg/clips/a", "freed_bytes": size_a}
    assert not (host / "home" / "zerg" / "clips" / "a").exists()

    # The cached listings are patched, not left stale.
    after = disk_usage.usage("/home/zerg/clips")
    assert [e["name"] for e in after["entries"]] == ["b.mp4"]
    home = disk_usage.usage("/home/zerg")
    clips = next(e for e in home["entries"] if e["name"] == "clips")
    assert clips["bytes"] == clips_before - size_a


def test_a_failed_rm_is_reported(host):
    write(host / "home" / "zerg" / "f.bin", 10)
    client = FakeClient(host, code=1)
    with pytest.raises(DiskUsageError, match="cannot remove"):
        disk_delete.delete(client, "/home/zerg/f.bin")
    assert client.helpers[0].removed
