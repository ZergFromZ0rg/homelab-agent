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
    summary = rebuild.summary_for(labels())
    assert summary["project"] == "media" and summary["service"] == "jellyfin"


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


def fake_client(project=None, exit_code=0, logs=b"", run_error=None):
    """A docker client whose containers.run() returns a helper that exits
    with `exit_code`."""
    client = mock.MagicMock()

    own = mock.MagicMock()
    own.labels = {"com.docker.compose.project": project} if project else {}
    own.image.tags = ["homelab-agent"]
    client.containers.get.return_value = own

    helper = mock.MagicMock()
    helper.short_id = "helper01"
    helper.wait.return_value = {"StatusCode": exit_code}
    helper.logs.return_value = logs
    client.containers.run.return_value = helper
    if run_error is not None:
        client.containers.run.side_effect = run_error

    client._helper = helper
    return client


def target(tmp_path, name="media"):
    url = f"https://github.com/zerg/{name}.git"
    return {
        "project": name,
        "service": "jellyfin",
        "working_dir": f"/srv/{name}",
        "path": str(tmp_path / "srv" / name),
        "remote": url,
        "fetch_url": url,
        "can_pull": True,
    }


def helper_kwargs(client):
    _, kwargs = client.containers.run.call_args
    return kwargs


def helper_script(client):
    return helper_kwargs(client)["command"][-1]


def test_a_rebuild_pulls_then_builds(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client(logs=b"built\n")

    finished = wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert finished["state"] == "done"
    # The pull names the url, not "origin" — see the ssh tests below.
    script = helper_script(client)
    assert script.index("pull --ff-only") < script.index("docker compose up")
    assert "https://github.com/zerg/media.git" in script
    assert script.startswith("git ")
    assert "docker compose up -d --build" in script
    assert finished["steps"][0]["output"] == "built\n"


def test_the_pull_can_be_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    wait_for(rebuild.start(client, target(tmp_path), pull=False)["id"])

    assert "git" not in helper_script(client)


def test_git_is_told_the_checkout_is_safe_to_touch(tmp_path, monkeypatch):
    """The helper runs as root against a checkout owned by whoever owns it
    on the host. Git has refused that since 2.35.2, so every pull would
    fail on "dubious ownership" without this."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert "-c safe.directory=/srv/media" in helper_script(client)


def test_a_failing_rebuild_keeps_its_output(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client(exit_code=1, logs=b"no space left on device\n")

    finished = wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert finished["state"] == "failed"
    assert "exited 1" in finished["error"]
    assert "no space left" in finished["steps"][0]["output"]


def test_the_helper_sees_the_project_at_its_real_host_path(tmp_path, monkeypatch):
    """Not the HOST_ROOT-prefixed one. Compose resolves a service's
    relative bind mounts against the directory it runs in, and the daemon
    on the other end of the socket only knows the real path."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    wait_for(rebuild.start(client, target(tmp_path))["id"])

    kwargs = helper_kwargs(client)
    assert kwargs["working_dir"] == "/srv/media"
    assert "/srv/media" in kwargs["volumes"]
    assert kwargs["volumes"]["/srv/media"]["bind"] == "/srv/media"
    assert "/var/run/docker.sock" in kwargs["volumes"]
    assert str(tmp_path) not in str(kwargs["volumes"])


def test_an_ordinary_rebuild_is_cleaned_up_after_its_output_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert helper_kwargs(client)["auto_remove"] is False
    client._helper.remove.assert_called_once()


def test_only_one_rebuild_at_a_time(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()
    client._helper.wait.side_effect = lambda **kw: time.sleep(0.2) or {"StatusCode": 0}

    first = rebuild.start(client, target(tmp_path))

    with pytest.raises(RuntimeError, match="already running"):
        rebuild.start(client, target(tmp_path, "other"))

    wait_for(first["id"], timeout=5)


def test_a_helper_that_will_not_start_fails_the_job(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client(run_error=RuntimeError("no such image"))

    finished = wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert finished["state"] == "failed"
    assert "no such image" in finished["error"]


def test_a_helper_that_vanishes_fails_the_job(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()
    client._helper.wait.side_effect = RuntimeError("timed out")

    finished = wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert finished["state"] == "failed"
    assert "lost track" in finished["error"]


# ---- rebuilding the agent itself -----------------------------------------


def test_replacing_this_agent_does_not_wait_for_a_result(tmp_path, monkeypatch):
    """compose up would kill the process waiting for it."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "abc123")
    client = fake_client(project="homelab")

    finished = wait_for(rebuild.start(client, target(tmp_path, "homelab"))["id"])

    assert finished["replaces_self"] is True
    assert finished["state"] == "handed_off"
    client._helper.wait.assert_not_called()
    # Nobody will be left to clean it up.
    assert helper_kwargs(client)["auto_remove"] is True


def test_another_project_on_the_same_host_is_not_a_self_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "abc123")
    client = fake_client(project="homelab")

    finished = wait_for(rebuild.start(client, target(tmp_path, "media"))["id"])

    assert finished["replaces_self"] is False
    assert finished["state"] == "done"


def test_the_helper_runs_this_agents_own_image_by_default(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "abc123")
    assert rebuild.helper_image(fake_client()) == "homelab-agent"

    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "docker:cli")
    assert rebuild.helper_image(fake_client()) == "docker:cli"


def test_no_entrypoint_override_is_needed(tmp_path, monkeypatch):
    """The agent image sets CMD, not ENTRYPOINT, so `command` replaces it
    outright. Passing entrypoint="" as well was cargo cult."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    wait_for(rebuild.start(client, target(tmp_path))["id"])

    assert "entrypoint" not in helper_kwargs(client)


# ---- job bookkeeping ------------------------------------------------------


def test_status_of_an_unknown_job_is_none():
    assert rebuild.status("nope") is None


def test_finished_jobs_are_kept_but_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setattr(rebuild, "MAX_JOBS", 3)

    for _ in range(5):
        wait_for(rebuild.start(fake_client(), target(tmp_path))["id"])

    assert len(rebuild.recent()) <= 3


# ---- remotes the helper can and can't pull from ---------------------------


def with_remote(tmp_path, url, name="media"):
    project = tmp_path / "srv" / name
    (project / ".git").mkdir(parents=True)
    (project / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n'
        f'[remote "origin"]\n\turl = {url}\n\tfetch = +refs/heads/*\n'
    )
    return project


def test_an_https_remote_can_be_pulled(tmp_path, monkeypatch):
    with_remote(tmp_path, "https://github.com/zerg/homelab-agent.git")
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    target = rebuild.target_for(labels())

    assert target["remote"] == "https://github.com/zerg/homelab-agent.git"
    assert target["can_pull"] is True


def test_an_ssh_remote_is_read_over_https_instead(tmp_path, monkeypatch):
    """ssh is the right way for a person to push and the wrong thing to
    hand a container. The same public repo is readable over https, and the
    url is derivable, so nothing on the host has to change."""
    with_remote(tmp_path, "git@github.com:zerg/homelab-dashboard.git")
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    target = rebuild.target_for(labels())

    assert target["remote"] == "git@github.com:zerg/homelab-dashboard.git"
    assert target["fetch_url"] == "https://github.com/zerg/homelab-dashboard.git"
    assert target["can_pull"] is True


def test_the_ssh_url_scheme_is_converted_too(tmp_path, monkeypatch):
    with_remote(tmp_path, "ssh://git@github.com/zerg/thing.git")
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    assert rebuild.target_for(labels())["fetch_url"] == (
        "https://github.com/zerg/thing.git"
    )


def test_a_self_hosted_ssh_remote_converts_too():
    assert rebuild.https_equivalent("git@gitlab.example.com:group/sub/proj.git") == (
        "https://gitlab.example.com/group/sub/proj.git"
    )


def test_an_https_remote_is_left_alone():
    url = "https://github.com/zerg/thing.git"
    assert rebuild.https_equivalent(url) == url


def test_something_that_is_not_a_url_is_not_guessed_at():
    """Better no pull than a fabricated remote."""
    assert rebuild.https_equivalent("/srv/local/repo") is None
    assert rebuild.https_equivalent(None) is None
    assert rebuild.can_pull("/srv/local/repo") is False


def test_the_pull_command_names_the_url_not_origin(tmp_path, monkeypatch):
    """Pulling from "origin" would use the ssh transport the remote is
    configured with, which is the thing that can't work in here."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    client = fake_client()

    target_with_ssh = {
        **target(tmp_path),
        "fetch_url": "https://github.com/zerg/media.git",
    }
    wait_for(rebuild.start(client, target_with_ssh)["id"])

    script = helper_script(client)
    assert "https://github.com/zerg/media.git" in script
    assert "pull --ff-only origin" not in script
    assert "rev-parse --abbrev-ref HEAD" in script


def test_a_checkout_with_no_origin_cannot_be_pulled(tmp_path, monkeypatch):
    project = tmp_path / "srv" / "media"
    (project / ".git").mkdir(parents=True)
    (project / ".git" / "config").write_text("[core]\n\tbare = false\n")
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    target = rebuild.target_for(labels())

    assert target["remote"] is None and target["can_pull"] is False


def test_only_the_origin_remote_is_read(tmp_path, monkeypatch):
    project = tmp_path / "srv" / "media"
    (project / ".git").mkdir(parents=True)
    (project / ".git" / "config").write_text(
        '[remote "upstream"]\n\turl = git@github.com:someone/else.git\n'
        '[remote "origin"]\n\turl = https://github.com/zerg/mine.git\n'
    )
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    assert rebuild.target_for(labels())["remote"] == "https://github.com/zerg/mine.git"


def test_an_unreadable_git_config_is_not_fatal(tmp_path, monkeypatch):
    project = tmp_path / "srv" / "media"
    (project / ".git").mkdir(parents=True)  # a .git with no config at all
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))

    target = rebuild.target_for(labels())

    assert target is not None and target["can_pull"] is False


def test_a_pull_that_cannot_work_is_refused_up_front(tmp_path, monkeypatch):
    """A remote that isn't a fetchable URL at all — better to say so than
    to let the helper fail halfway."""
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    unfetchable = {
        "project": "local-thing", "service": "app",
        "working_dir": "/srv/local", "path": str(tmp_path),
        "remote": "/srv/mirror/local.git", "fetch_url": None,
        "can_pull": False,
    }

    with pytest.raises(ValueError, match="can't fetch|http"):
        rebuild.start(fake_client(), unfetchable)

    # The same target builds fine without the pull.
    finished = wait_for(rebuild.start(fake_client(), unfetchable, pull=False)["id"])
    assert finished["state"] == "done"


def test_the_summary_shows_the_configured_remote_and_that_it_is_pullable(tmp_path, monkeypatch):
    with_remote(tmp_path, "git@github.com:zerg/x.git")
    monkeypatch.setattr(rebuild, "HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("REBUILD_ENABLED", "1")

    summary = rebuild.summary_for(labels())

    # The remote shown is the one configured; the pull works anyway.
    assert summary["remote"] == "git@github.com:zerg/x.git"
    assert summary["can_pull"] is True
