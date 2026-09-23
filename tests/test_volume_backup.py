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
    monkeypatch.delenv("BACKUP_HOST_DIR", raising=False)
    monkeypatch.delenv("BACKUP_SOURCE_DIRS", raising=False)
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
    """A hand-configured root that nobody mounted. The answer is one
    compose line, and reporting it beats a bare 'not allowed'.

    ``/backups`` has its own, better message — see
    ``test_the_placeholder_volume_is_not_a_destination`` — because that one
    is set up with a variable, not by editing YAML."""
    monkeypatch.setenv("BACKUP_DIRS", "/mnt/nas")
    client = FakeClient(own_mounts=[mount("/host", "/", rw=False)])

    (root,) = volume_backup.roots(client)

    assert root["usable"] is False
    assert "/mnt/nas" in root["problem"]
    assert "volumes" in root["problem"]


def test_the_standard_mount_points_at_the_variable_that_sets_it(monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", "/backups")
    client = FakeClient(own_mounts=[mount("/host", "/", rw=False)])

    (root,) = volume_backup.roots(client)

    assert root["usable"] is False
    assert "BACKUP_HOST_DIR" in root["problem"]


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


# ---- directory sources ----------------------------------------------------


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A fake host filesystem mounted at HOST_ROOT, the way the agent sees
    the real one."""
    root = tmp_path / "host"
    (root / "home/zerg/ai-librarian/data/qdrant").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    monkeypatch.setenv("HOST_ROOT", str(root))
    return root


def test_directories_are_refused_until_the_host_opts_in(host):
    with pytest.raises(volume_backup.PolicyError, match="BACKUP_SOURCE_DIRS"):
        volume_backup.resolve_source("/home/zerg/ai-librarian/data/qdrant")


def test_a_directory_resolves_to_its_host_spelling(host, monkeypatch):
    """The daemon resolves a bind mount on the host, so it must be handed
    the host path — not the HOST_ROOT-prefixed one the agent reads through.
    Handing over the wrong one gets an empty directory Docker creates."""
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")

    resolved = volume_backup.resolve_source("/home/zerg/ai-librarian/data/qdrant")

    assert resolved == "/home/zerg/ai-librarian/data/qdrant"
    assert str(host) not in resolved


def test_a_source_root_can_be_backed_up_exactly(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg/ai-librarian")

    assert volume_backup.resolve_source("/home/zerg/ai-librarian") == (
        "/home/zerg/ai-librarian"
    )


def test_a_directory_outside_every_root_is_refused(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg/ai-librarian")

    with pytest.raises(volume_backup.PolicyError, match="not under a backup source"):
        volume_backup.resolve_source("/etc")


def test_a_directory_source_refuses_dot_dot(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")

    with pytest.raises(volume_backup.PolicyError, match=r"\.\."):
        volume_backup.resolve_source("/home/zerg/../etc")


def test_a_source_that_is_not_a_directory_is_refused(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")

    with pytest.raises(volume_backup.PolicyError, match="not a directory"):
        volume_backup.resolve_source("/home/zerg/nothing-here")


def test_a_symlink_out_of_the_root_is_refused(host, monkeypatch):
    """An allowed root someone can drop a symlink into is not a boundary
    unless the link is resolved before the comparison."""
    (host / "home/zerg/escape").symlink_to(host / "etc")
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg/ai-librarian")

    with pytest.raises(volume_backup.PolicyError):
        volume_backup.resolve_source("/home/zerg/escape")


def test_a_relative_source_is_refused(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")

    with pytest.raises(volume_backup.PolicyError, match="absolute"):
        volume_backup.resolve_source("home/zerg")


def test_a_paths_archive_name_is_stable_and_unique():
    name = volume_backup.archive_name("/home/zerg/ai-librarian/data/qdrant", 1790000000)

    assert name.startswith("home-zerg-ai-librarian-data-qdrant-")
    assert name.endswith(".tar.gz")
    assert "/" not in name


def test_containers_using_a_directory_are_found_by_bind_mount():
    def bind(source):
        return {"Type": "bind", "Source": source}

    path = "/home/zerg/ai-librarian/data/qdrant"

    assert volume_backup._uses([bind(path)], None, path), "the exact directory"
    assert volume_backup._uses([bind(path + "/segments")], None, path), "one under it"
    assert volume_backup._uses([bind("/home/zerg/ai-librarian")], None, path), (
        "a container mounting the parent writes into it too"
    )
    assert not volume_backup._uses([bind("/home/zerg/other")], None, path)
    assert not volume_backup._uses([bind("/home/zerg/ai-librarian/data/qdrant2")], None, path)


def test_a_job_takes_a_volume_or_a_path_but_not_both(host, monkeypatch, tmp_path):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")
    client = FakeClient(volumes=[FakeVolume("qdrant")])

    with pytest.raises(volume_backup.PolicyError, match="not both"):
        volume_backup.start(
            client, volume="qdrant", path="/home/zerg", directory="/backups"
        )

    with pytest.raises(volume_backup.PolicyError, match="either a volume or a path"):
        volume_backup.start(client, directory="/backups")


def test_a_directory_job_checks_the_source_before_starting(host, monkeypatch):
    """It has to fail here, not inside a helper container nobody is
    watching yet."""
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg")
    client = FakeClient()

    with pytest.raises(volume_backup.PolicyError, match="not under a backup source"):
        volume_backup.start(client, path="/etc", directory="/backups")


def test_backup_host_dir_is_enough_on_its_own(monkeypatch):
    """The one-variable setup. Two settings that had to agree were one too
    many: out of step, the agent comes up fine and quietly stores nothing,
    which is exactly what happened on the real fleet."""
    assert volume_backup.configured_dirs() == []

    monkeypatch.setenv("BACKUP_HOST_DIR", "/home/zerg/backups")

    assert volume_backup.configured_dirs() == ["/backups"]
    assert volume_backup.enabled() is True


def test_backup_dirs_still_names_roots_directly(monkeypatch):
    monkeypatch.setenv("BACKUP_DIRS", "/mnt/nas/backups")

    assert volume_backup.configured_dirs() == ["/mnt/nas/backups"]


def test_the_two_settings_do_not_duplicate_the_mount(monkeypatch):
    monkeypatch.setenv("BACKUP_HOST_DIR", "/home/zerg/backups")
    monkeypatch.setenv("BACKUP_DIRS", "/backups")

    assert volume_backup.configured_dirs() == ["/backups"]


def test_the_placeholder_volume_is_not_a_destination(monkeypatch):
    """compose binds a named volume at /backups when BACKUP_HOST_DIR is
    unset. It is writable, so without this it reads as a configured
    destination and archives go quietly into a volume nobody looks in."""
    monkeypatch.setenv("BACKUP_DIRS", "/backups")
    client = FakeClient(own_mounts=[{
        "Type": "volume",
        "Name": "homelab-agent_agent-backups-unset",
        "Destination": "/backups",
        "Source": "/var/lib/docker/volumes/homelab-agent_agent-backups-unset/_data",
        "RW": True,
    }])

    (root,) = volume_backup.roots(client)

    assert root["usable"] is False
    assert "BACKUP_HOST_DIR" in root["problem"]


def test_a_real_directory_at_the_mount_is_a_destination(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_HOST_DIR", "/home/zerg/backups")
    client = FakeClient(own_mounts=[{
        "Type": "bind", "Destination": str(tmp_path),
        "Source": "/home/zerg/backups", "RW": True,
    }])
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))

    usable = [r for r in volume_backup.roots(client) if r["usable"]]

    assert [r["host_path"] for r in usable] == ["/home/zerg/backups"]


# ---- sizing and candidates ------------------------------------------------


def test_measure_counts_files_not_directories(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.bin").write_bytes(b"x" * 1000)
    (tmp_path / "sub" / "b.bin").write_bytes(b"y" * 2000)
    volume_backup.forget_sizes()

    out = volume_backup.measure(str(tmp_path))

    assert out == {"bytes": 3000, "files": 2, "partial": False}


def test_measure_does_not_follow_symlinks(tmp_path):
    """Following one would double-count at best and walk out of the tree at
    worst."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "big.bin").write_bytes(b"x" * 5000)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link").symlink_to(real)
    volume_backup.forget_sizes()

    assert volume_backup.measure(str(tree))["bytes"] == 0


def test_measure_gives_up_rather_than_hanging(tmp_path, monkeypatch):
    """A media library is a long walk, and the form asking for this size
    has to get an answer."""
    for i in range(50):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / "f").write_bytes(b"x" * 10)

    volume_backup.forget_sizes()
    out = volume_backup.measure(str(tmp_path), budget=-1)

    assert out["partial"] is True


def test_measure_is_cached(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 100)
    volume_backup.forget_sizes()

    first = volume_backup.measure(str(tmp_path))
    (tmp_path / "b.bin").write_bytes(b"y" * 100)

    assert volume_backup.measure(str(tmp_path)) == first, "second read is cached"


def test_candidates_are_the_bind_mounts_a_host_allows(host, monkeypatch):
    """Not a file browser — the agent has no business listing the host.
    These are the directories containers actually write to."""
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg/ai-librarian")
    volume_backup.forget_sizes()

    client = FakeClient(containers=[
        FakeContainer("qdrant-1", mounts=[
            {"Type": "bind", "Source": "/home/zerg/ai-librarian/data/qdrant"},
        ]),
        FakeContainer("elsewhere", mounts=[
            {"Type": "bind", "Source": "/etc/passwd"},
        ]),
    ])

    paths = [c["path"] for c in volume_backup.candidate_dirs(client)]

    assert "/home/zerg/ai-librarian/data/qdrant" in paths
    assert "/home/zerg/ai-librarian" in paths, "the root itself is offered"
    assert "/etc/passwd" not in paths, "outside the allowed roots"


def test_candidates_carry_who_uses_them(host, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg/ai-librarian")
    volume_backup.forget_sizes()

    client = FakeClient(containers=[
        FakeContainer("qdrant-1", mounts=[
            {"Type": "bind", "Source": "/home/zerg/ai-librarian/data/qdrant"},
        ]),
    ])

    found = {c["path"]: c for c in volume_backup.candidate_dirs(client)}

    assert found["/home/zerg/ai-librarian/data/qdrant"]["in_use_by"] == ["qdrant-1"]


def test_no_candidates_until_the_host_opts_in():
    assert volume_backup.candidate_dirs(FakeClient()) == []


def test_the_agents_own_placeholder_is_not_offered_as_a_source(monkeypatch):
    """It exists precisely because nothing is stored there."""
    client = FakeClient(volumes=[
        FakeVolume("homelab-agent_agent-backups-unset"),
        FakeVolume("qdrant"),
    ])

    assert [v["name"] for v in volume_backup.list_volumes(client)] == ["qdrant"]


def test_anonymous_volumes_sort_below_named_ones():
    """A dozen 64-hex volumes above the real ones buries the answer."""
    client = FakeClient(volumes=[
        FakeVolume("f" * 64),
        FakeVolume("uptime-kuma_data"),
        FakeVolume("a" * 64),
        FakeVolume("jellyfin_config"),
    ])

    names = [v["name"] for v in volume_backup.list_volumes(client)]

    assert names[:2] == ["jellyfin_config", "uptime-kuma_data"]
    assert names[2:] == ["a" * 64, "f" * 64]
