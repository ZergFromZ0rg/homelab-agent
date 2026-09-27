"""Image updates. The registry conversation and the comparison run on
fakes; the round trip at the bottom uses a throwaway local registry and
real `docker compose`, when there's a daemon and a local agent image."""

import sys
import time
from datetime import datetime
from unittest import mock

import pytest

if "main" in sys.modules:
    import main  # noqa: F401
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main  # noqa: F401

import updates


@pytest.mark.parametrize("ref, expected", [
    ("jellyfin/jellyfin:latest", ("registry-1.docker.io", "jellyfin/jellyfin", "latest")),
    ("busybox", ("registry-1.docker.io", "library/busybox", "latest")),
    ("busybox:1.37.0", ("registry-1.docker.io", "library/busybox", "1.37.0")),
    ("docker.io/library/nginx:alpine", ("registry-1.docker.io", "library/nginx", "alpine")),
    ("lscr.io/linuxserver/qbittorrent:latest", ("lscr.io", "linuxserver/qbittorrent", "latest")),
    ("ghcr.io/gethomepage/homepage", ("ghcr.io", "gethomepage/homepage", "latest")),
    ("localhost:5000/app:v2", ("localhost:5000", "app", "v2")),
])
def test_split_ref(ref, expected):
    assert updates.split_ref(ref) == expected


def test_local_name():
    assert updates.local_name("jellyfin/jellyfin:latest") == ("jellyfin/jellyfin", "latest")
    assert updates.local_name("busybox") == ("busybox", "latest")
    assert updates.local_name("localhost:5000/app:v2") == ("localhost:5000/app", "v2")


class Response:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


INDEX = {"manifests": [
    {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
    {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
    {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}},
]}


def fake_registry(monkeypatch, manifest_status=200):
    calls = []

    class Session:
        def __init__(self):
            self.headers = {}

        def get(self, url, headers=None, params=None, timeout=None):
            calls.append((url, dict(self.headers), params))
            if "token" in url:
                return Response(200, {"token": "t0k"})
            if "Authorization" not in self.headers:
                return Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.example/token",service="registry.example"'})
            return Response(manifest_status, INDEX, {"Docker-Content-Digest": "sha256:index"})

    monkeypatch.setattr(updates.requests, "Session", Session)
    return calls


def test_the_bearer_challenge_and_the_platform_pick(monkeypatch):
    calls = fake_registry(monkeypatch)
    got = updates.remote_digests("jellyfin/jellyfin:latest", {"os": "linux", "architecture": "amd64"})
    assert got == {"index": "sha256:index", "platform": "sha256:amd"}
    assert calls[1][2] == {"service": "registry.example", "scope": "repository:jellyfin/jellyfin:pull"}
    assert calls[2][1]["Authorization"] == "Bearer t0k"


def local(platform_digest, index=("sha256:index",)):
    return {"platform": platform_digest, "platform_info": {"os": "linux", "architecture": "amd64"},
            "index": list(index)}


def test_compares_the_platform_not_the_index(monkeypatch):
    fake_registry(monkeypatch)
    # Index moved (re-published), our platform's image didn't: current.
    monkeypatch.setattr(updates, "local_digests", lambda c, i: local("sha256:amd", index=("sha256:old-index",)))
    assert updates.check_ref(None, "x/y:latest", "img")["state"] == "current"
    monkeypatch.setattr(updates, "local_digests", lambda c, i: local("sha256:older-amd"))
    assert updates.check_ref(None, "x/y:latest", "img")["state"] == "available"


def test_local_builds_and_pinned_digests(monkeypatch):
    fake_registry(monkeypatch, manifest_status=404)
    monkeypatch.setattr(updates, "local_digests", lambda c, i: local("sha256:x"))
    assert updates.check_ref(None, "homelab-agent", "img")["state"] == "local"
    assert updates.check_ref(None, "nginx@sha256:abc", "img")["state"] == "pinned"


def container(ref="nginx:alpine", image="sha256:img", labels=None):
    c = mock.MagicMock()
    c.attrs = {"Config": {"Image": ref}, "Image": image}
    return c


def test_for_container(monkeypatch):
    monkeypatch.setitem(updates._cache, "nginx:alpine", {"state": "available", "image_id": "sha256:img", "checked_at": 1})
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    compose = {"com.docker.compose.project": "web"}
    assert updates.for_container(container(), compose)["can_update"] is True
    assert "Compose" in updates.for_container(container(), {})["why_not"]
    assert updates.for_container(container(image="sha256:newer"), compose)["state"] == "unchecked"
    monkeypatch.delenv("REBUILD_ENABLED")
    assert updates.for_container(container(), compose)["can_update"] is False


def test_nightly_timing():
    at = "03:30"
    assert not updates._due(at, datetime(2026, 9, 27, 3, 29), None)
    assert updates._due(at, datetime(2026, 9, 27, 3, 30), None)
    assert updates._due(at, datetime(2026, 9, 27, 3, 55), None)
    assert not updates._due(at, datetime(2026, 9, 27, 3, 31), "2026-09-27")
    assert not updates._due(at, datetime(2026, 9, 27, 4, 0), None)
    assert not updates._due("junk", datetime(2026, 9, 27, 3, 30), None)


# --- the real thing ----------------------------------------------------------

docker = pytest.importorskip("docker")
HELPER = "homelab-agent-termtest"
try:
    _real = docker.from_env()
    _real.ping()
    _real.images.get(HELPER)
    _READY = True
except Exception:  # noqa: BLE001
    _READY = False

needs_docker = pytest.mark.skipif(not _READY, reason=f"needs Docker and a local {HELPER} image")
PORT = 5055
REF = f"localhost:{PORT}/hlupdate:stable"


def push(dockerfile: str):
    import io
    image, _ = _real.images.build(fileobj=io.BytesIO(dockerfile.encode()), tag=REF, rm=True)
    for line in _real.images.push(REF, stream=True, decode=True):
        if "error" in line:
            raise RuntimeError(line["error"])
    return image.id


@pytest.fixture
def registry_and_stack(tmp_path, monkeypatch):
    registry = _real.containers.run("registry:2", detach=True, ports={"5000/tcp": PORT},
                                    labels={"homelab-agent-test": "updates"})
    time.sleep(2)
    root = tmp_path.resolve()
    (root / "compose.yml").write_text(
        f"services:\n  app:\n    image: {REF}\n    restart: unless-stopped\n"
    )
    project = f"hlupd{root.name[-6:].lower().replace('_', '')}"
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setattr(updates.compose_edit.rebuild, "helper_image", lambda client: HELPER)
    monkeypatch.setattr(updates.rebuild, "self_project", lambda client: None)
    monkeypatch.setattr(updates.compose_edit, "WATCH_SECONDS", 6)
    updates._cache.clear()
    yield project, root
    for c in _real.containers.list(all=True, filters={"label": f"com.docker.compose.project={project}"}):
        c.remove(force=True)
    for n in _real.networks.list(names=[f"{project}_default"]):
        n.remove()
    registry.remove(force=True)
    for tag in (REF, REF.replace(":stable", ":hl-rollback-app")):
        try:
            _real.images.remove(tag, force=True)
        except Exception:  # noqa: BLE001
            pass


def up(project, root):
    import subprocess
    subprocess.run(["docker", "compose", "-p", project, "-f", str(root / "compose.yml"), "up", "-d"],
                   check=True, capture_output=True)
    return _real.containers.list(filters={"label": f"com.docker.compose.project={project}"})[0]


def wait(job_id):
    for _ in range(180):
        job = updates.status(job_id)
        if job["state"] != "running":
            return job
        time.sleep(1)
    raise AssertionError("never finished")


@needs_docker
def test_check_update_and_roll_back(registry_and_stack):
    project, root = registry_and_stack
    v1 = push('FROM alpine:3\nCMD ["sleep", "600"]\n')
    app = up(project, root)

    updates.check_all(_real)
    assert updates.for_container(app, app.labels)["state"] == "current"

    push('FROM alpine:3\nRUN echo two > /v\nCMD ["sleep", "600"]\n')
    _real.images.get(v1).tag(*updates.local_name(REF))  # the host still has v1 under the tag
    updates.check_all(_real)
    app.reload()
    assert updates.for_container(app, app.labels)["state"] == "available"

    job = wait(updates.start(_real, [app.name])["id"])
    assert job["state"] == "done", job
    app = _real.containers.get(app.name)
    assert app.image.id != v1 and app.status == "running"
    good = app.image.id

    push('FROM alpine:3\nCMD ["sh", "-c", "exit 1"]\n')
    _real.images.get(good).tag(*updates.local_name(REF))
    updates.check_all(_real)
    job = wait(updates.start(_real, [app.name])["id"])

    assert job["state"] == "rolled_back", job
    app = _real.containers.get(app.name)
    assert app.image.id == good and app.status == "running"
    # Nothing left pinning old images.
    assert not [t for i in _real.images.list() for t in i.tags if "hl-rollback" in t]
