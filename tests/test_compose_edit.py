"""Container settings. The watch and the generator run on fakes; the
round trips at the bottom drive real `docker compose` through the helper
when there's a daemon and a locally built agent image to use as it."""

import sys
from unittest import mock

import pytest
import yaml

if "main" in sys.modules:
    import main  # noqa: F401
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main  # noqa: F401

import compose_edit


class FakeContainer:
    def __init__(self, name, states):
        self.name = name
        self._states = list(states)
        self.attrs = {}
        self._first = True

    def reload(self):
        if not self._first and len(self._states) > 1:
            self._states.pop(0)
        self._first = False
        status, code, health, restarts = self._states[0]
        self.attrs = {
            "State": {"Status": status, "ExitCode": code,
                      "Health": {"Status": health} if health else None},
            "RestartCount": restarts,
        }


def fake_client(*containers):
    client = mock.MagicMock()
    client.containers.list.return_value = list(containers)
    return client


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run_watch(*containers, seconds=10):
    clock = Clock()
    return compose_edit.watch(fake_client(*containers), "p", seconds=seconds,
                              sleep=clock.sleep, clock=clock)


def test_a_healthy_project_passes():
    assert run_watch(FakeContainer("web", [("running", 0, None, 0)])) is None


def test_a_finished_one_shot_is_fine():
    assert run_watch(FakeContainer("init", [("exited", 0, None, 0)])) is None


def test_a_crash_fails_with_the_exit_code():
    failed = run_watch(FakeContainer("web", [("running", 0, None, 0), ("exited", 1, None, 0)]))
    assert failed["name"] == "web" and "code 1" in failed["why"]


def test_a_restart_loop_fails():
    failed = run_watch(FakeContainer("web", [("running", 0, None, 2), ("running", 0, None, 3)]))
    assert "restarting" in failed["why"]


def test_unhealthy_fails_and_starting_is_waited_for():
    assert "unhealthy" in run_watch(FakeContainer("db", [("running", 0, "unhealthy", 0)]))["why"]
    slow = FakeContainer("db", [("running", 0, "starting", 0)] * 6 + [("running", 0, "healthy", 0)])
    assert run_watch(slow, seconds=3) is None
    never = FakeContainer("db", [("running", 0, "starting", 0)])
    assert "never passed" in run_watch(never, seconds=3)["why"]


def test_not_compose():
    client = mock.MagicMock()
    client.containers.get.return_value.labels = {}
    client.containers.get.return_value.name = "node-exporter"
    with pytest.raises(compose_edit.NotCompose):
        compose_edit.target(client, "x")


def test_generate_keeps_only_what_the_container_adds():
    client = mock.MagicMock()
    container = client.containers.get.return_value
    container.name = "node-exporter"
    container.attrs = {
        "Config": {"Image": "prom/node-exporter", "Env": ["PATH=/bin", "EXTRA=1"],
                   "Cmd": ["--path.rootfs=/host"]},
        "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "NetworkMode": "host",
                       "PidMode": "host", "Binds": ["/:/host:ro"],
                       "PortBindings": {"9100/tcp": [{"HostIp": "", "HostPort": "9100"}]}},
        "Mounts": [],
    }
    client.images.get.return_value.attrs = {"Config": {"Env": ["PATH=/bin"], "Cmd": []}}

    service = yaml.safe_load(compose_edit.generate(client, "x")["generated"])["services"]["node-exporter"]

    assert service == {
        "image": "prom/node-exporter", "container_name": "node-exporter",
        "restart": "unless-stopped", "network_mode": "host", "pid": "host",
        "ports": ["9100:9100"], "volumes": ["/:/host:ro"], "environment": ["EXTRA=1"],
        "command": ["--path.rootfs=/host"],
    }


def test_the_agents_own_stack_is_refused(monkeypatch):
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setattr(compose_edit.rebuild, "self_project", lambda client: "homelab-agent")
    assert "own stack" in compose_edit.why_not_apply(None, {"project": "homelab-agent"})
    monkeypatch.delenv("REBUILD_ENABLED")
    assert "doesn't allow" in compose_edit.why_not_apply(None, {"project": "media"})


# --- real compose ------------------------------------------------------------

docker = pytest.importorskip("docker")
HELPER = "homelab-agent-termtest"
try:
    _real = docker.from_env()
    _real.ping()
    _real.images.get(HELPER)
    _READY = True
except Exception:  # noqa: BLE001
    _READY = False

needs_compose = pytest.mark.skipif(not _READY, reason=f"needs Docker and a local {HELPER} image")

GOOD = "services:\n  web:\n    image: alpine:3\n    command: sleep 300\n    # keep me\n"


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    (root / "compose.yml").write_text(GOOD)
    name = f"hltest{root.name[-6:].lower().replace('_', '')}"
    monkeypatch.setenv("HOST_ROOT", "")
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    monkeypatch.setenv("FILES_WRITABLE_PATHS", str(root))
    monkeypatch.setattr(compose_edit.files, "_roots_cache", None)
    monkeypatch.setattr(compose_edit.rebuild, "helper_image", lambda client: HELPER)
    monkeypatch.setattr(compose_edit.rebuild, "self_project", lambda client: None)
    monkeypatch.setattr(compose_edit, "WATCH_SECONDS", 6)
    info = {"project": name, "working_dir": str(root), "files": [str(root / "compose.yml")],
            "service": "web", "container": f"{name}-web-1"}
    monkeypatch.setattr(compose_edit, "target", lambda client, cid: dict(info))
    yield info, root
    for c in _real.containers.list(all=True, filters={"label": f"com.docker.compose.project={name}"}):
        c.remove(force=True)
    for n in _real.networks.list(names=[f"{name}_default"]):
        n.remove()


def wait(job_id):
    import time
    for _ in range(120):
        job = compose_edit.status(job_id)
        if job["state"] != "running":
            return job
        time.sleep(1)
    raise AssertionError("job never finished")


@needs_compose
def test_preview_checks_without_touching_the_file(project):
    info, root = project
    bad = compose_edit.preview(_real, "x", info["files"][0], "services:\n  web:\n    image: [\n")
    assert bad["valid"] is False and "compose.yml" in bad["error"]
    good = compose_edit.preview(_real, "x", info["files"][0], GOOD.replace("300", "400"))
    assert good["valid"] and "-    command: sleep 300" in good["diff"]
    assert (root / "compose.yml").read_text() == GOOD


@needs_compose
def test_apply_brings_it_up_and_a_crash_rolls_back(project):
    info, root = project
    path = info["files"][0]

    job = wait(compose_edit.start(_real, "x", path, GOOD, None, None)["id"])
    assert job["state"] == "done", job
    assert _real.containers.get(info["container"]).status == "running"

    crashing = GOOD.replace("command: sleep 300", "command: sh -c 'sleep 2; exit 3'\n    restart: \"no\"")
    job = wait(compose_edit.start(_real, "x", path, crashing, (root / "compose.yml").stat().st_mtime, None)["id"])

    assert job["state"] == "rolled_back", job
    assert "code 3" in job["error"]
    assert (root / "compose.yml").read_text() == GOOD
    assert "# keep me" in (root / "compose.yml").read_text()
    assert _real.containers.get(info["container"]).status == "running"
