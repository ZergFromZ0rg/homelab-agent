"""The /rebuild routes. Docker is stubbed at import like the connections
route tests, so these run without a daemon."""

import sys
import time
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import rebuild


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    monkeypatch.delenv("REBUILD_ENABLED", raising=False)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    rebuild._jobs.clear()
    yield
    rebuild._jobs.clear()


@pytest.fixture
def client():
    return TestClient(main.app)


def a_container(project="media", working_dir="/srv/media"):
    container = mock.MagicMock()
    container.name = "jellyfin"
    container.labels = {
        "com.docker.compose.project": project,
        "com.docker.compose.service": "jellyfin",
        "com.docker.compose.project.working_dir": working_dir,
    }
    return container


def test_rebuilds_are_refused_until_the_host_opts_in(client):
    resp = client.post("/rebuild", json={"container": "jellyfin"})

    assert resp.status_code == 403
    assert "REBUILD_ENABLED" in resp.json()["detail"]


def test_a_container_is_required(client, monkeypatch):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    assert client.post("/rebuild", json={}).status_code == 400


def test_a_container_without_a_git_checkout_is_refused(client, monkeypatch):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setattr(main, "find_container_or_404", lambda cid: a_container())

    resp = client.post("/rebuild", json={"container": "jellyfin"})

    assert resp.status_code == 400
    assert "nothing to pull" in resp.json()["detail"]


def test_starting_a_rebuild_returns_a_job_to_poll(client, monkeypatch, tmp_path):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    git_dir = tmp_path / "srv" / "media" / ".git"
    git_dir.mkdir(parents=True)
    git_dir.joinpath("config").write_text(
        '[remote "origin"]\n\turl = https://github.com/zerg/media.git\n'
    )
    monkeypatch.setattr(main, "find_container_or_404", lambda cid: a_container())

    helper = mock.MagicMock()
    helper.short_id = "helper01"
    helper.wait.return_value = {"StatusCode": 0}
    helper.logs.return_value = b"ok\n"
    main.client.containers.run.return_value = helper

    job = client.post("/rebuild", json={"container": "jellyfin"}).json()

    assert job["project"] == "media" and job["state"] in ("running", "done")

    polled = client.get(f"/rebuild/{job['id']}")
    assert polled.status_code == 200 and polled.json()["id"] == job["id"]

    # The working directory the helper is given is the host's real one,
    # not the HOST_ROOT-prefixed path the agent reads through.
    deadline = time.monotonic() + 3
    while main.client.containers.run.call_args is None and time.monotonic() < deadline:
        time.sleep(0.01)
    _, kwargs = main.client.containers.run.call_args
    assert kwargs["working_dir"] == "/srv/media"


def test_an_unknown_job_is_a_404(client, monkeypatch):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    assert client.get("/rebuild/nope").status_code == 404


def test_the_listing_reports_whether_it_is_enabled(client, monkeypatch):
    assert client.get("/rebuild").json() == {"enabled": False, "jobs": []}

    monkeypatch.setenv("REBUILD_ENABLED", "1")
    assert client.get("/rebuild").json()["enabled"] is True


def test_every_rebuild_route_is_token_gated(client, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")

    assert client.get("/rebuild").status_code == 401
    assert client.get("/rebuild/anything").status_code == 401
    assert client.post("/rebuild", json={"container": "x"}).status_code == 401

    headers = {"X-Agent-Token": "sekret"}
    assert client.get("/rebuild", headers=headers).status_code == 200


def test_an_ssh_remote_pulls_fine_over_https(client, monkeypatch, tmp_path):
    """The dashboard repo's case. ssh is the right way for a person to
    push and the wrong thing to give a container, so the same public repo
    is read over https — without touching the host's config."""
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    git_dir = tmp_path / "srv" / "media" / ".git"
    git_dir.mkdir(parents=True)
    git_dir.joinpath("config").write_text(
        '[remote "origin"]\n\turl = git@github.com:zerg/media.git\n'
    )
    monkeypatch.setattr(main, "find_container_or_404", lambda cid: a_container())

    helper = mock.MagicMock()
    helper.wait.return_value = {"StatusCode": 0}
    helper.logs.return_value = b""
    main.client.containers.run.return_value = helper

    resp = client.post("/rebuild", json={"container": "jellyfin"})

    assert resp.status_code == 200
    assert resp.json()["fetch_url"] == "https://github.com/zerg/media.git"


def test_the_agents_own_container_can_be_rebuilt(client, monkeypatch, tmp_path):
    """Protection stops the control routes stopping or deleting the agent.
    It must not stop /rebuild — replacing the agent with a newer build is
    the whole reason this route exists."""
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setattr(main, "PROTECTED_CONTAINERS", {"homelab-agent"})

    git_dir = tmp_path / "srv" / "agent" / ".git"
    git_dir.mkdir(parents=True)
    git_dir.joinpath("config").write_text(
        '[remote "origin"]\n\turl = https://github.com/zerg/homelab-agent.git\n'
    )

    agent = a_container(project="homelab-agent", working_dir="/srv/agent")
    agent.name = "homelab-agent"
    monkeypatch.setattr(main, "find_container_or_404", lambda cid: agent)

    helper = mock.MagicMock()
    helper.wait.return_value = {"StatusCode": 0}
    helper.logs.return_value = b""
    main.client.containers.run.return_value = helper

    resp = client.post("/rebuild", json={"container": "homelab-agent"})

    assert resp.status_code == 200
    assert resp.json()["project"] == "homelab-agent"


def test_the_control_routes_still_refuse_a_protected_container(client, monkeypatch):
    monkeypatch.setattr(main, "PROTECTED_CONTAINERS", {"homelab-agent"})

    protected = mock.MagicMock()
    protected.name = "homelab-agent"
    monkeypatch.setattr(main.client.containers, "get", lambda cid: protected)

    resp = client.post("/containers/homelab-agent/stop")

    assert resp.status_code == 403
    assert "protected" in resp.json()["detail"]


def test_rebuild_self_finds_its_own_container(client, monkeypatch, tmp_path):
    """The caller shouldn't have to know which container the agent is;
    guessing by name breaks as soon as someone renames it."""
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setenv("HOSTNAME", "abc123")

    git_dir = tmp_path / "srv" / "agent" / ".git"
    git_dir.mkdir(parents=True)
    git_dir.joinpath("config").write_text(
        '[remote "origin"]\n\turl = https://github.com/zerg/homelab-agent.git\n'
    )

    agent = a_container(project="homelab-agent", working_dir="/srv/agent")
    agent.labels["com.docker.compose.project"] = "homelab-agent"
    looked_up = []
    monkeypatch.setattr(
        main, "find_container_or_404",
        lambda cid: looked_up.append(cid) or agent,
    )
    monkeypatch.setattr(
        rebuild, "self_project", lambda client: "homelab-agent"
    )

    helper = mock.MagicMock()
    helper.short_id = "h1"
    main.client.containers.run.return_value = helper

    job = client.post("/rebuild/self").json()

    assert looked_up == ["abc123"], "it looks itself up by its own hostname"
    assert job["replaces_self"] is True
    assert job["state"] == "handed_off"


def test_rebuild_self_needs_the_host_to_have_opted_in(client, monkeypatch):
    monkeypatch.setenv("HOSTNAME", "abc123")
    assert client.post("/rebuild/self").status_code == 403


def test_rebuild_self_is_token_gated(client, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")
    assert client.post("/rebuild/self").status_code == 401


def test_rebuild_self_on_an_agent_not_run_from_a_checkout(client, monkeypatch, tmp_path):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setenv("HOSTNAME", "abc123")

    plain = a_container(project=None, working_dir=None)
    plain.labels = {}
    monkeypatch.setattr(main, "find_container_or_404", lambda cid: plain)

    resp = client.post("/rebuild/self")

    assert resp.status_code == 400
    assert "nothing to pull" in resp.json()["detail"]
