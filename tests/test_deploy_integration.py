"""Real end-to-end: the FastAPI app talks to the real Docker daemon.

Skipped automatically when no daemon is reachable (CI without Docker, a
dev box with Docker Desktop stopped). Pulls a tiny public image
(traefik/whoami, ~7 MB) on first run.
"""

import random
import time
import uuid

import pytest

docker = pytest.importorskip("docker")

try:
    _client = docker.from_env()
    _client.ping()
    _DOCKER = True
except Exception:  # noqa: BLE001
    _DOCKER = False

pytestmark = pytest.mark.skipif(not _DOCKER, reason="no Docker daemon reachable")

IMAGE = "traefik/whoami:latest"


def _wait_until(predicate, timeout=10.0, interval=0.5):
    """The agent's /containers list is rebuilt by a background worker, so a
    just-created container appears with a short lag even after the route's
    cache nudge. Poll for it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ALLOWED_HOST_PATHS", "/tmp")
    monkeypatch.setenv("AGENT_TOKEN", "")
    from fastapi.testclient import TestClient

    import main

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def cleanup():
    made = []
    yield made
    c = docker.from_env()
    for name in made:
        try:
            c.containers.get(name).remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def test_create_list_delete_roundtrip(client, cleanup):
    name = f"itest-{uuid.uuid4().hex[:8]}"
    cleanup.append(name)

    host_port = random.randint(21000, 29000)
    resp = client.post(
        "/containers",
        json={
            "image": IMAGE,
            "name": name,
            "ports": [{"container": 80, "host": host_port}],
            "resources": {"memory_mb": 64},
            "labels": {"deployed-by": "homelab-dashboard"},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    container_id = body["id"]

    # It shows up in the snapshot the dashboard polls, with the label.
    def _find():
        for c in client.get("/containers").json()["containers"]:
            if c["name"] == name:
                return c
        return None

    mine = _wait_until(_find)
    assert mine is not None, "container never appeared in /containers"
    assert mine["deployed_by"] == "homelab-dashboard"
    assert mine["status"] == "running"

    # Delete it.
    resp = client.request("DELETE", f"/containers/{container_id}")
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    gone = _wait_until(lambda: _find() is None)
    assert gone, "container still listed after delete"


def test_policy_rejection_is_not_run(client):
    resp = client.post(
        "/containers",
        json={
            "image": IMAGE,
            "name": f"itest-{uuid.uuid4().hex[:8]}",
            "volumes": [{"source": "/etc", "target": "/host-etc"}],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["stage"] == "policy"


def test_name_collision(client, cleanup):
    name = f"itest-{uuid.uuid4().hex[:8]}"
    cleanup.append(name)

    first = client.post("/containers", json={"image": IMAGE, "name": name})
    assert first.status_code == 200

    second = client.post("/containers", json={"image": IMAGE, "name": name})
    assert second.status_code == 400
    assert second.json()["stage"] == "create"
