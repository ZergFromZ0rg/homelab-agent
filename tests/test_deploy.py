import docker
import pytest

import deploy
from deploy import (
    CreateContainerRequest,
    PolicyError,
    check_policy,
    normalize_image,
)


class FakeImage:
    attrs = {"RepoDigests": ["nginx@sha256:abc"]}


class FakeContainer:
    def __init__(self, name="c1", cid="abcdef123456"):
        self.name = name
        self.short_id = cid[:12]
        self.image = FakeImage()

    def reload(self):
        pass


class FakeClient:
    """Just enough of docker.DockerClient for deploy.deploy()."""

    def __init__(self, existing=None, pull_error=None, run_error=None):
        self._existing = set(existing or [])
        self._pull_error = pull_error
        self._run_error = run_error
        self.pulled = []
        self.run_calls = []

        outer = self

        class Containers:
            def get(self, name):
                if name in outer._existing:
                    return FakeContainer(name=name)
                raise docker.errors.NotFound(f"no such container {name}")

            def run(self, image, **kwargs):
                if outer._run_error:
                    raise outer._run_error
                outer.run_calls.append((image, kwargs))
                return FakeContainer(name=kwargs.get("name", "generated"))

        class Images:
            def pull(self, image):
                if outer._pull_error:
                    raise outer._pull_error
                outer.pulled.append(image)

        self.containers = Containers()
        self.images = Images()


def req(**kwargs):
    base = {"image": "nginx:latest"}
    base.update(kwargs)
    return CreateContainerRequest(**base)


# ---- normalize_image ---------------------------------------------------


@pytest.mark.parametrize(
    "given,expected",
    [
        ("nginx", "nginx:latest"),
        ("nginx:1.27", "nginx:1.27"),
        ("lscr.io/linuxserver/jellyfin", "lscr.io/linuxserver/jellyfin:latest"),
        ("lscr.io/linuxserver/jellyfin:latest", "lscr.io/linuxserver/jellyfin:latest"),
        ("registry:5000/app", "registry:5000/app:latest"),
        ("app@sha256:deadbeef", "app@sha256:deadbeef"),
    ],
)
def test_normalize_image(given, expected):
    assert normalize_image(given) == expected


# ---- policy ----------------------------------------------------------


def test_protected_name_rejected():
    with pytest.raises(PolicyError):
        check_policy(req(name="homelab-agent"))


def test_registry_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_REGISTRIES", ["lscr.io", "docker.io"])
    check_policy(req(image="nginx:latest"))  # implicit docker.io -> ok
    check_policy(req(image="lscr.io/linuxserver/jellyfin"))
    with pytest.raises(PolicyError):
        check_policy(req(image="ghcr.io/someone/app:latest"))


def test_host_path_needs_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    with pytest.raises(PolicyError):
        check_policy(req(volumes=[{"source": "/etc/passwd", "target": "/x"}]))

    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", ["/srv/appdata"])
    check_policy(req(volumes=[{"source": "/srv/appdata/jelly", "target": "/config"}]))
    with pytest.raises(PolicyError):
        check_policy(req(volumes=[{"source": "/srv/other", "target": "/x"}]))


def test_named_volume_always_allowed(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    check_policy(req(volumes=[{"source": "jellyfin-config", "target": "/config"}]))


def test_docker_socket_never_allowed(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", ["/var/run"])
    with pytest.raises(PolicyError):
        check_policy(
            req(volumes=[{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}])
        )


# ---- deploy ---------------------------------------------------------


def test_deploy_happy_path():
    client = FakeClient()
    result = deploy.deploy(
        client,
        req(
            name="jelly",
            ports=[{"container": 8096, "host": 8096}],
            volumes=[{"source": "jelly-config", "target": "/config"}],
            resources={"cpus": 2, "memory_mb": 2048},
        ),
    )
    assert result["success"] is True
    assert result["id"] == "abcdef123456"
    assert client.pulled == ["nginx:latest"]

    image, kwargs = client.run_calls[0]
    assert image == "nginx:latest"
    assert kwargs["ports"] == {"8096/tcp": 8096}
    assert kwargs["volumes"] == {"jelly-config": {"bind": "/config", "mode": "rw"}}
    assert kwargs["nano_cpus"] == 2_000_000_000
    assert kwargs["mem_limit"] == "2048m"
    assert kwargs["restart_policy"] == {"Name": "unless-stopped"}
    assert kwargs["labels"]["managed-by"] == "homelab-agent"


def test_deploy_name_collision():
    client = FakeClient(existing={"jelly"})
    with pytest.raises(PolicyError) as exc:
        deploy.deploy(client, req(name="jelly"))
    assert exc.value.stage == "create"


def test_deploy_pull_failure():
    client = FakeClient(pull_error=docker.errors.APIError("manifest unknown"))
    with pytest.raises(PolicyError) as exc:
        deploy.deploy(client, req())
    assert exc.value.stage == "pull"


def test_deploy_skips_pull_when_disabled():
    client = FakeClient()
    deploy.deploy(client, req(pull=False))
    assert client.pulled == []


def test_deploy_restart_no_omits_policy():
    client = FakeClient()
    deploy.deploy(client, req(restart_policy="no"))
    _, kwargs = client.run_calls[0]
    assert "restart_policy" not in kwargs
