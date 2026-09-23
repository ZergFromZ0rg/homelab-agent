"""The /backup/volumes and /backup/receive routes. Docker is stubbed at
import like the other route tests, so these run without a daemon."""

import hashlib
import sys
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import volume_backup
from tests.test_volume_backup import FakeClient, FakeVolume, mount


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("BACKUP_DIRS", raising=False)
    monkeypatch.delenv("BACKUP_PUBLIC_URL", raising=False)
    monkeypatch.delenv("AGENT_URL", raising=False)
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    monkeypatch.setenv("HOSTNAME", "agentcontainer")
    volume_backup.reset()
    yield
    volume_backup.reset()


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def store(tmp_path, monkeypatch):
    """This agent with one usable backup root."""
    monkeypatch.setenv("BACKUP_DIRS", str(tmp_path))
    fake = FakeClient(
        own_mounts=[mount(str(tmp_path), "/srv/backups")],
        volumes=[FakeVolume("qdrant", project="ai-librarian")],
    )
    monkeypatch.setattr(main, "client", fake)
    return tmp_path


def test_listing_says_what_can_be_read_and_what_can_be_written(client, store):
    body = client.get("/backup/volumes").json()

    assert [v["name"] for v in body["volumes"]] == ["qdrant"]
    assert body["store"]["enabled"] is True
    assert body["store"]["roots"][0]["usable"] is True


def test_a_host_that_stores_nothing_says_so_with_the_fix(client, monkeypatch):
    monkeypatch.setattr(main, "client", FakeClient())

    store = client.get("/backup/volumes").json()["store"]

    assert store["enabled"] is False
    assert store["roots"] == []


def test_the_receive_url_prefers_the_public_override(client, store, monkeypatch):
    """A registered url can be a container name the dashboard resolves on
    its own network. Another *host's* helper can't use that."""
    monkeypatch.setenv("AGENT_URL", "http://homelab-agent:8123")
    assert client.get("/backup/volumes").json()["store"]["receive_url"] == (
        "http://homelab-agent:8123"
    )

    monkeypatch.setenv("BACKUP_PUBLIC_URL", "http://thinkpad:8123")
    assert client.get("/backup/volumes").json()["store"]["receive_url"] == (
        "http://thinkpad:8123"
    )


def test_running_without_a_volume_is_a_400(client, store):
    assert client.post("/backup/volumes/run", json={}).status_code == 400


def test_a_volume_that_is_not_here_is_a_400_not_a_500(client, store):
    resp = client.post(
        "/backup/volumes/run", json={"volume": "ghost", "directory": str(store)}
    )

    assert resp.status_code == 400
    assert "no volume named" in resp.json()["detail"]


def test_a_destination_outside_the_roots_is_refused(client, store):
    resp = client.post(
        "/backup/volumes/run", json={"volume": "qdrant", "directory": "/etc"}
    )

    assert resp.status_code == 400
    assert "not under a backup directory" in resp.json()["detail"]


def test_an_unknown_job_is_a_404(client, store):
    assert client.get("/backup/volumes/jobs/nope").status_code == 404


def test_receiving_writes_the_archive_and_reports_its_digest(client, store):
    payload = b"archive" * 5000
    name = volume_backup.archive_name("qdrant")

    resp = client.post(
        "/backup/receive",
        content=payload,
        headers={"X-Backup-Dir": str(store), "X-Backup-Name": name},
    )

    assert resp.status_code == 200
    assert resp.json()["sha256"] == hashlib.sha256(payload).hexdigest()
    assert (store / name).read_bytes() == payload


def test_receiving_into_a_subdirectory_creates_it(client, store):
    name = volume_backup.archive_name("qdrant")

    resp = client.post(
        "/backup/receive",
        content=b"x",
        headers={"X-Backup-Dir": f"{store}/bigboy", "X-Backup-Name": name},
    )

    assert resp.status_code == 200
    assert (store / "bigboy" / name).is_file()


def test_receiving_refuses_a_directory_outside_the_roots(client, store):
    resp = client.post(
        "/backup/receive",
        content=b"x",
        headers={"X-Backup-Dir": "/etc", "X-Backup-Name": "x-20260101-000000.tar.gz"},
    )

    assert resp.status_code == 400


def test_receiving_refuses_a_name_that_climbs_out(client, store):
    resp = client.post(
        "/backup/receive",
        content=b"x",
        headers={"X-Backup-Dir": str(store), "X-Backup-Name": "../escape.tar.gz"},
    )

    assert resp.status_code == 400
    assert not (store.parent / "escape.tar.gz").exists()


def test_the_store_routes_need_the_token(client, store, monkeypatch):
    """Everything here writes to the host filesystem or reads a volume, so
    none of it is open when a token is set."""
    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")

    for call in (
        lambda h: client.get("/backup/volumes", headers=h),
        lambda h: client.post("/backup/volumes/run", json={"volume": "qdrant"}, headers=h),
        lambda h: client.get(f"/backup/archives?directory={store}", headers=h),
        lambda h: client.post("/backup/archives/delete",
                              json={"directory": str(store), "names": []}, headers=h),
        lambda h: client.post("/backup/receive", content=b"x", headers={
            **h, "X-Backup-Dir": str(store), "X-Backup-Name": "a-20260101-000000.tar.gz",
        }),
    ):
        assert call({}).status_code == 401
        assert call({"X-Agent-Token": "sekret"}).status_code != 401


def test_listing_and_deleting_archives(client, store):
    name = "qdrant-20260101-000000.tar.gz"
    (store / name).write_bytes(b"x")

    listed = client.get(f"/backup/archives?directory={store}").json()
    assert [a["name"] for a in listed["archives"]] == [name]

    out = client.post(
        "/backup/archives/delete", json={"directory": str(store), "names": [name]}
    ).json()

    assert out["deleted"] == [name]
    assert not (store / name).exists()


def test_deleting_needs_a_list_of_names(client, store):
    resp = client.post(
        "/backup/archives/delete", json={"directory": str(store), "names": "all"}
    )

    assert resp.status_code == 400


def test_the_listing_says_which_directories_may_be_backed_up(client, store, monkeypatch):
    assert client.get("/backup/volumes").json()["sources"]["dirs"] == []

    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/home/zerg, /srv/data")

    assert client.get("/backup/volumes").json()["sources"]["dirs"] == [
        "/home/zerg", "/srv/data",
    ]


def test_running_with_neither_a_volume_nor_a_path_is_a_400(client, store):
    resp = client.post("/backup/volumes/run", json={"directory": str(store)})

    assert resp.status_code == 400
    assert "volume or a path" in resp.json()["detail"]


def test_a_directory_source_is_refused_until_the_host_opts_in(client, store):
    resp = client.post(
        "/backup/volumes/run",
        json={"path": "/home/zerg/ai-librarian", "directory": str(store)},
    )

    assert resp.status_code == 400
    assert "BACKUP_SOURCE_DIRS" in resp.json()["detail"]


def test_the_projects_route_reports_what_would_be_lost(client, store, monkeypatch):
    import volume_backup

    monkeypatch.setattr(volume_backup, "projects", lambda c: [
        {"project": "jellyfin", "working_dir": "/srv/jellyfin",
         "containers": ["jellyfin"], "volumes": [], "directories": []},
    ])

    body = client.get("/backup/projects").json()

    assert body["host"]
    assert [p["project"] for p in body["projects"]] == ["jellyfin"]
    assert body["source_dirs"] == []


def test_the_projects_route_needs_the_token(client, store, monkeypatch):
    import main

    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")

    assert client.get("/backup/projects").status_code == 401


def test_the_store_route_answers_without_measuring_anything(client, store, monkeypatch):
    """"Can I send backups here" must not cost a walk of every volume on
    the host — that is minutes on a big one."""
    import volume_backup

    def explode(*args, **kwargs):
        raise AssertionError("the store route must not measure anything")

    monkeypatch.setattr(volume_backup, "measure", explode)
    monkeypatch.setattr(volume_backup, "list_volumes", explode)
    monkeypatch.setattr(volume_backup, "candidate_dirs", explode)

    body = client.get("/backup/store").json()

    assert body["enabled"] is True
    assert body["roots"][0]["usable"] is True
    assert body["encrypted"] is False


def test_the_store_route_needs_the_token(client, store, monkeypatch):
    import main

    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")
    assert client.get("/backup/store").status_code == 401
