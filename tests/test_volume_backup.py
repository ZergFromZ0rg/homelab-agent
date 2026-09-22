"""The policy and bookkeeping half of volume backups.

The part that actually reads a volume needs a Docker daemon and lives in
``test_backup_helper.py`` (no daemon needed — it runs the helper directly)
and ``test_volume_backup_integration.py`` (a real daemon, auto-skipped).
"""

import hashlib
import os
from unittest import mock

import pytest

import volume_backup


class FakeVolume:
    def __init__(self, name, project=None, driver="local"):
        self.name = name
        self.attrs = {
            "Name": name,
            "Driver": driver,
            "CreatedAt": "2026-09-01T00:00:00Z",
            "Labels": {"com.docker.compose.project": project} if project else {},
        }


class FakeContainer:
    def __init__(self, name, volumes=(), mounts=None):
        self.name = name
        self.attrs = {
            "Mounts": mounts if mounts is not None else [
                {"Type": "volume", "Name": v} for v in volumes
            ]
        }
        self.stopped = False
        self.started = False

    def stop(self, timeout=None):
        self.stopped = True

    def start(self):
        self.started = True


class FakeClient:
    """Enough of docker-py for the policy code: this agent's own container
    (for the mount table), the volumes, and who is using them."""

    def __init__(self, own_mounts=(), volumes=(), containers=()):
        agent = FakeContainer("homelab-agent")
        agent.attrs = {"Mounts": list(own_mounts)}

        self.containers = mock.Mock()
        self.containers.get.return_value = agent
        self.containers.list.side_effect = lambda all=False: list(containers)

        self.volumes = mock.Mock()
        self.volumes.list.return_value = list(volumes)
        self.volumes.get.side_effect = self._get_volume
        self._volumes = {v.attrs["Name"]: v for v in volumes}

    def _get_volume(self, name):
        if name not in self._volumes:
            raise KeyError(name)
        return self._volumes[name]


def mount(container_path, host_path, rw=True):
    return {"Destination": container_path, "Source": host_path, "RW": rw}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("BACKUP_DIRS", raising=False)
    monkeypatch.setenv("HOSTNAME", "agentcontainer")
    volume_backup.reset()
    yield
    volume_backup.reset()


# ---- policy ---------------------------------------------------------------


def test_a_host_with_no_backup_dirs_stores_nothing():
    assert volume_backup.enabled() is False


def test_enabled_once_backup_dirs_is_set(monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", "/backups")
    assert volume_backup.enabled() is True


def test_a_root_that_is_not_mounted_says_what_to_add(monkeypatch):
    """The commonest misconfiguration, and the answer is one compose line.
    Reporting it beats a bare 'not allowed'."""
    monkeypatch.setenv("BACKUP_DIRS", "/backups")
    client = FakeClient(own_mounts=[mount("/host", "/", rw=False)])

    (root,) = volume_backup.roots(client)

    assert root["usable"] is False
    assert "/backups" in root["problem"]
    assert "volumes" in root["problem"]


def test_a_read_only_mount_is_not_a_backup_root(monkeypatch):
    """``-v /:/host:ro`` is already there for the other features. It must
    not accidentally become somewhere backups can be written."""
    monkeypatch.setenv("BACKUP_DIRS", "/host/srv")
    client = FakeClient(own_mounts=[mount("/host/srv", "/srv", rw=False)])

    (root,) = volume_backup.roots(client)

    assert root["usable"] is False


def test_resolve_maps_a_subdirectory_to_its_host_path(tmp_path, monkeypatch):
    """The two spellings of a destination are the whole reason this
    function exists: the daemon needs the host one."""
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    client = FakeClient(own_mounts=[mount(str(tmp_path), "/srv/backups")])

    path, host_path = volume_backup.resolve(client, f"{tmp_path}/bigboy/qdrant")

    assert path == tmp_path / "bigboy" / "qdrant"
    assert host_path == "/srv/backups/bigboy/qdrant"


def test_resolve_refuses_a_directory_outside_every_root(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    client = FakeClient(own_mounts=[mount(str(tmp_path), "/srv/backups")])

    with pytest.raises(volume_backup.PolicyError, match="not under a backup directory"):
        volume_backup.resolve(client, "/etc")


def test_resolve_refuses_dot_dot(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    client = FakeClient(own_mounts=[mount(str(tmp_path), "/srv/backups")])

    with pytest.raises(volume_backup.PolicyError, match=r"\.\."):
        volume_backup.resolve(client, f"{tmp_path}/../etc")


def test_resolve_refuses_a_symlink_out_of_the_root(tmp_path, monkeypatch):
    """A writable root someone can drop a symlink into is not a boundary
    unless the symlink is resolved before the comparison."""
    root = tmp_path / "backups"
    root.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (root / "escape").symlink_to(outside)

    monkeypatch.setenv("BACKUP_DIRS", str(root))
    client = FakeClient(own_mounts=[mount(str(root), "/srv/backups")])

    with pytest.raises(volume_backup.PolicyError, match="resolves outside"):
        volume_backup.resolve(client, str(root / "escape"))


def test_resolve_explains_itself_when_nothing_is_configured():
    client = FakeClient()

    with pytest.raises(volume_backup.PolicyError, match="BACKUP_DIRS"):
        volume_backup.resolve(client, "/backups")


# ---- names ----------------------------------------------------------------


def test_archive_name_is_sortable_and_carries_the_volume():
    name = volume_backup.archive_name("ai-librarian_qdrant", 1790000000)
    assert name.startswith("ai-librarian_qdrant-")
    assert name.endswith(".tar.gz")


def test_archive_name_sanitizes_an_awkward_volume_name():
    assert "/" not in volume_backup.archive_name("a/b", 1790000000)


@pytest.mark.parametrize("name", [
    "../escape.tar.gz",
    "/etc/passwd.tar.gz",
    "plain.txt",
    "",
    "nested/thing.tar.gz",
])
def test_check_name_refuses_anything_that_is_not_an_archive_name(name):
    with pytest.raises(volume_backup.PolicyError):
        volume_backup.check_name(name)


def test_check_name_accepts_one_this_agent_generated():
    name = volume_backup.archive_name("qdrant")
    assert volume_backup.check_name(name) == name


# ---- stored archives ------------------------------------------------------


def _root(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    return FakeClient(own_mounts=[mount(str(tmp_path), "/srv/backups")])


def test_listing_archives_is_newest_first_and_ignores_other_files(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    (tmp_path / "a-20260101-000000.tar.gz").write_bytes(b"a")
    (tmp_path / "b-20260202-000000.tar.gz").write_bytes(b"bb")
    (tmp_path / "notes.txt").write_text("ignore me")
    (tmp_path / "half.tar.gz.part").write_bytes(b"incomplete")
    os.utime(tmp_path / "a-20260101-000000.tar.gz", (1, 1))
    os.utime(tmp_path / "b-20260202-000000.tar.gz", (2, 2))

    archives = volume_backup.list_archives(client, str(tmp_path))

    assert [a["name"] for a in archives] == [
        "b-20260202-000000.tar.gz", "a-20260101-000000.tar.gz",
    ]
    assert archives[0]["bytes"] == 2


def test_deleting_reports_what_was_not_there(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    (tmp_path / "gone-20260101-000000.tar.gz").write_bytes(b"x")

    out = volume_backup.delete_archives(
        client, str(tmp_path),
        ["gone-20260101-000000.tar.gz", "never-20260101-000000.tar.gz"],
    )

    assert out["deleted"] == ["gone-20260101-000000.tar.gz"]
    assert out["missing"] == ["never-20260101-000000.tar.gz"]
    assert not (tmp_path / "gone-20260101-000000.tar.gz").exists()


def test_deleting_refuses_a_name_that_is_a_path(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    secret = tmp_path.parent / "secret.tar.gz"
    secret.write_bytes(b"x")

    with pytest.raises(volume_backup.PolicyError):
        volume_backup.delete_archives(client, str(tmp_path), ["../secret.tar.gz"])

    assert secret.exists(), "it must not have escaped the directory"


# ---- receiving ------------------------------------------------------------


def test_receiver_hashes_and_renames_into_place(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    name = volume_backup.archive_name("qdrant")
    payload = b"some archive bytes" * 100

    receiver = volume_backup.Receiver(client, str(tmp_path), name)
    assert (tmp_path / f"{name}.part").exists(), "it writes to .part first"

    for i in range(0, len(payload), 64):
        receiver.write(payload[i:i + 64])

    out = receiver.commit()

    assert out["bytes"] == len(payload)
    assert out["sha256"] == hashlib.sha256(payload).hexdigest()
    assert (tmp_path / name).read_bytes() == payload
    assert not (tmp_path / f"{name}.part").exists()


def test_an_aborted_upload_leaves_nothing_behind(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    name = volume_backup.archive_name("qdrant")

    receiver = volume_backup.Receiver(client, str(tmp_path), name)
    receiver.write(b"half an archive")
    receiver.abort()

    assert list(tmp_path.iterdir()) == []


def test_receiving_creates_the_subdirectory(tmp_path, monkeypatch):
    client = _root(tmp_path, monkeypatch)
    name = volume_backup.archive_name("qdrant")

    volume_backup.Receiver(client, f"{tmp_path}/bigboy/qdrant", name).abort()

    assert (tmp_path / "bigboy" / "qdrant").is_dir()


# ---- volumes --------------------------------------------------------------


def test_listing_volumes_says_what_is_using_each_one():
    client = FakeClient(
        volumes=[FakeVolume("qdrant", project="ai-librarian"), FakeVolume("other")],
        containers=[
            FakeContainer("qdrant-1", volumes=["qdrant"]),
            FakeContainer("api", volumes=["qdrant", "other"]),
        ],
    )

    volumes = {v["name"]: v for v in volume_backup.list_volumes(client)}

    assert volumes["qdrant"]["in_use_by"] == ["api", "qdrant-1"]
    assert volumes["qdrant"]["project"] == "ai-librarian"
    assert volumes["other"]["in_use_by"] == ["api"]


# ---- starting a job -------------------------------------------------------


def test_starting_refuses_a_volume_that_is_not_here(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    client = FakeClient(own_mounts=[mount(str(tmp_path), "/srv/backups")])

    with pytest.raises(volume_backup.PolicyError, match="no volume named"):
        volume_backup.start(client, volume="ghost", directory=str(tmp_path))


def test_starting_refuses_a_remote_destination_that_is_not_a_url():
    client = FakeClient(volumes=[FakeVolume("qdrant")])

    with pytest.raises(volume_backup.PolicyError, match="http"):
        volume_backup.start(
            client, volume="qdrant", directory="/backups",
            remote={"url": "thinkpad:8123"},
        )


def test_a_local_job_checks_the_destination_before_starting():
    """The volume is fine; the destination is not. It has to fail here, not
    inside a helper container whose output nobody is watching yet."""
    client = FakeClient(volumes=[FakeVolume("qdrant")])

    with pytest.raises(volume_backup.PolicyError):
        volume_backup.start(client, volume="qdrant", directory="/nowhere")


def test_quiesce_stops_users_but_never_a_protected_container():
    client = FakeClient(containers=[
        FakeContainer("qdrant-1", volumes=["qdrant"]),
        FakeContainer("homelab-agent", volumes=["qdrant"]),
        FakeContainer("unrelated", volumes=["other"]),
    ])

    stopped, skipped = volume_backup._quiesce(client, "qdrant")

    assert [c.name for c in stopped] == ["qdrant-1"]
    assert skipped == ["homelab-agent"]
    assert all(c.stopped for c in stopped)


def test_resume_starts_them_again_in_reverse():
    containers = [FakeContainer("a"), FakeContainer("b")]

    assert volume_backup._resume(containers) == []
    assert all(c.started for c in containers)
