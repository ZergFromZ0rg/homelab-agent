import time
from unittest import mock

import pytest

import rebuild


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("REBUILD_ENABLED", raising=False)
    monkeypatch.delenv("REBUILD_HELPER_IMAGE", raising=False)
    monkeypatch.delenv("HOSTNAME", raising=False)
    rebuild._jobs.clear()
    yield
    rebuild._jobs.clear()


def labels(project="media", service="jellyfin", working_dir="/srv/media"):
    out = {}
    if project:
        out["com.docker.compose.project"] = project
    if service:
        out["com.docker.compose.service"] = service
    if working_dir:
        out["com.docker.compose.project.working_dir"] = working_dir
    return out


def checkout(tmp_path, name="media"):
    """A directory that looks like a Compose project in a git checkout."""
    project = tmp_path / "srv" / name
    (project / ".git").mkdir(parents=True)
    (project / "compose.yml").write_text("services: {}\n")
    return project


# ---- opting in ------------------------------------------------------------


def test_it_is_off_unless_asked_for(monkeypatch):
    assert rebuild.enabled() is False
    monkeypatch.setenv("REBUILD_ENABLED", "1")
    assert rebuild.enabled() is True
    monkeypatch.setenv("REBUILD_ENABLED", "0")
    assert rebuild.enabled() is False


def test_the_container_summary_is_silent_while_off(tmp_path, monkeypatch):
    checkout(tmp_path)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    assert rebuild.summary_for(labels()) is None

    monkeypatch.setenv("REBUILD_ENABLED", "1")
    assert rebuild.summary_for(labels()) == {
        "project": "media", "service": "jellyfin"
    }


# ---- what counts as a target ---------------------------------------------


def test_a_compose_project_in_a_git_checkout_is_a_target(tmp_path, monkeypatch):
    project = checkout(tmp_path)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    target = rebuild.target_for(labels())

    assert target["project"] == "media"
    assert target["working_dir"] == "/srv/media"
    assert target["path"] == str(project)


def test_a_container_compose_never_started_is_not_a_target(tmp_path, monkeypatch):
    checkout(tmp_path)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    assert rebuild.target_for({}) is None
    assert rebuild.target_for(labels(project=None)) is None
    assert rebuild.target_for(labels(working_dir=None)) is None


def test_a_project_that_is_not_a_git_checkout_is_not_a_target(tmp_path, monkeypatch):
    plain = tmp_path / "srv" / "media"
    plain.mkdir(parents=True)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    assert rebuild.target_for(labels()) is None


def test_a_working_dir_that_is_gone_is_not_a_target(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    assert rebuild.target_for(labels(working_dir="/srv/deleted")) is None


def test_host_paths_are_read_through_the_mount(monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", "/host")
    assert str(rebuild.host_path("/srv/media")) == "/host/srv/media"

    monkeypatch.setattr(rebuild, "HOST_ROOT", "/")
    assert str(rebuild.host_path("/srv/media")) == "/srv/media"


# ---- running one ----------------------------------------------------------


def wait_for(job_id, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = rebuild.status(job_id)
        if job and job["state"] != "running":
            return job
        time.sleep(0.01)
    raise AssertionError("job never finished")


def fake_client(project=None):
    client = mock.MagicMock()
    container = mock.MagicMock()
    container.labels = {"com.docker.compose.project": project} if project else {}
    container.image.tags = ["homelab-agent"]
    client.containers.get.return_value = container
    return client


def target(tmp_path, name="media"):
    return {
        "project": name,
        "service": "jellyfin",
        "working_dir": f"/srv/{name}",
        "path": str(tmp_path / "srv" / name),
    }


def test_a_rebuild_pulls_then_builds(tmp_path, monkeypatch):
    checkout(tmp_path)
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    calls = []

    def fake_run(args, cwd, timeout):
        calls.append((args, cwd))
        return {"command": " ".join(args), "exit_code": 0, "output": "", "seconds": 0.1}

    monkeypatch.setattr(rebuild, "_run", fake_run)

    job = rebuild.start(fake_client(), target(tmp_path))
    finished = wait_for(job["id"])

    assert finished["state"] == "done"
    assert [c[0] for c in calls] == [
        ["git", "pull", "--ff-only", "origin"],
        ["docker", "compose", "up", "-d", "--build"],
    ]
    assert calls[0][1] == str(tmp_path / "srv" / "media")


def test_the_pull_can_be_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    calls = []
    monkeypatch.setattr(
        rebuild, "_run",
        lambda args, cwd, timeout: calls.append(args) or
        {"command": "", "exit_code": 0, "output": "", "seconds": 0},
    )

    job = rebuild.start(fake_client(), target(tmp_path), pull=False)
    wait_for(job["id"])

    assert calls == [["docker", "compose", "up", "-d", "--build"]]


def test_a_failed_pull_stops_before_building(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    calls = []

    def fake_run(args, cwd, timeout):
        calls.append(args)
        return {"command": " ".join(args), "exit_code": 1,
                "output": "diverged from origin", "seconds": 0.1}

    monkeypatch.setattr(rebuild, "_run", fake_run)

    finished = wait_for(rebuild.start(fake_client(), target(tmp_path))["id"])

    assert finished["state"] == "failed"
    assert finished["error"] == "git pull failed"
    assert len(calls) == 1
    assert "diverged" in finished["steps"][0]["output"]


def test_a_failed_build_is_reported_with_its_output(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    def fake_run(args, cwd, timeout):
        failed = args[0] == "docker"
        return {"command": " ".join(args), "exit_code": 1 if failed else 0,
                "output": "no space left on device" if failed else "", "seconds": 0}

    monkeypatch.setattr(rebuild, "_run", fake_run)

    finished = wait_for(rebuild.start(fake_client(), target(tmp_path))["id"])

    assert finished["state"] == "failed" and finished["error"] == "compose up failed"
    assert "no space left" in finished["steps"][-1]["output"]


def test_only_one_rebuild_at_a_time(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setattr(
        rebuild, "_run",
        lambda args, cwd, timeout: time.sleep(0.2) or
        {"command": "", "exit_code": 0, "output": "", "seconds": 0},
    )

    first = rebuild.start(fake_client(), target(tmp_path))

    with pytest.raises(RuntimeError, match="already running"):
        rebuild.start(fake_client(), target(tmp_path, "other"))

    wait_for(first["id"], timeout=5)


# ---- rebuilding the agent itself -----------------------------------------


def test_replacing_this_agent_is_handed_to_a_helper(tmp_path, monkeypatch):
    """compose up would kill the process running it, so it can't be us."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "abc123")

    client = fake_client(project="homelab")
    client.containers.run.return_value = mock.MagicMock(short_id="helper01")

    direct = []
    monkeypatch.setattr(rebuild, "_run", lambda *a, **k: direct.append(a) or {})

    job = rebuild.start(client, target(tmp_path, "homelab"))
    finished = wait_for(job["id"])

    assert finished["replaces_self"] is True
    assert finished["state"] == "handed_off"
    assert direct == []  # nothing was run in this process

    _, kwargs = client.containers.run.call_args
    assert kwargs["detach"] is True and kwargs["remove"] is True
    assert kwargs["working_dir"] == "/srv/homelab"
    assert "/var/run/docker.sock" in kwargs["volumes"]
    script = kwargs["command"][-1]
    assert "git pull --ff-only origin" in script
    assert "docker compose up -d --build" in script


def test_another_project_on_the_same_host_is_not_a_self_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "abc123")
    monkeypatch.setattr(
        rebuild, "_run",
        lambda *a, **k: {"command": "", "exit_code": 0, "output": "", "seconds": 0},
    )

    client = fake_client(project="homelab")
    finished = wait_for(rebuild.start(client, target(tmp_path, "media"))["id"])

    assert finished["replaces_self"] is False
    assert finished["state"] == "done"
    client.containers.run.assert_not_called()


def test_a_helper_that_will_not_start_fails_the_job(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "abc123")

    client = fake_client(project="homelab")
    client.containers.run.side_effect = RuntimeError("no such image")

    finished = wait_for(rebuild.start(client, target(tmp_path, "homelab"))["id"])

    assert finished["state"] == "failed"
    assert "no such image" in finished["error"]


def test_the_helper_runs_this_agents_own_image_by_default(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "abc123")
    assert rebuild.helper_image(fake_client()) == "homelab-agent"

    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "docker:cli")
    assert rebuild.helper_image(fake_client()) == "docker:cli"


# ---- job bookkeeping ------------------------------------------------------


def test_status_of_an_unknown_job_is_none():
    assert rebuild.status("nope") is None


def test_finished_jobs_are_kept_but_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setattr(rebuild, "MAX_JOBS", 3)
    monkeypatch.setattr(
        rebuild, "_run",
        lambda *a, **k: {"command": "", "exit_code": 0, "output": "", "seconds": 0},
    )

    for _ in range(5):
        wait_for(rebuild.start(fake_client(), target(tmp_path))["id"])

    assert len(rebuild.recent()) <= 3


def test_run_captures_output_and_exit_code(tmp_path):
    step = rebuild._run(["sh", "-c", "echo hello; exit 3"], str(tmp_path), 10)

    assert step["exit_code"] == 3
    assert "hello" in step["output"]
    assert step["command"] == "sh -c 'echo hello; exit 3'"


def test_run_reports_a_missing_binary_rather_than_raising(tmp_path):
    step = rebuild._run(["definitely-not-a-binary"], str(tmp_path), 10)
    assert step["exit_code"] == 127


def test_run_reports_a_timeout(tmp_path):
    step = rebuild._run(["sh", "-c", "sleep 5"], str(tmp_path), 1)
    assert step["exit_code"] == 124 and "timed out" in step["output"]
