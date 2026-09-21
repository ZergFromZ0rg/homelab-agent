"""Pull and rebuild a Compose project on this host, on request.

Every other mutating route here works against a policy allowlist — which
registries, which host paths, which compose keys — because the agent talks
to the host daemon as root and the dashboard is on the other side of a
shared token. This route is different in kind: ``git pull`` runs whatever
hooks the repo carries and ``--build`` runs whatever the Dockerfile says,
so it is arbitrary code execution on the host, on purpose.

That is why it is **off unless ``REBUILD_ENABLED`` is set**. A host that
hasn't opted in cannot be made to build anything by anything the dashboard
sends, and says so rather than pretending the route doesn't exist.

A target is any container Compose started (the project, service and
working directory are all on its labels) whose working directory is a git
repo. Nothing else is rebuildable, because there'd be nothing to pull.

  REBUILD_ENABLED       "1" to turn the route on. Off by default.
  REBUILD_TIMEOUT       seconds for the whole pull + build (default 1800).
  REBUILD_HELPER_IMAGE  image for the self-rebuild helper below; defaults
                        to this agent's own image, which already carries
                        git, the Docker CLI and the Compose plugin.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time
import uuid
from pathlib import Path

from log import audit, log

TIMEOUT = int(os.getenv("REBUILD_TIMEOUT", "1800"))

# Where the host filesystem is mounted, so a label's absolute path can be
# read from in here. Same knob the backup worker uses.
HOST_ROOT = os.getenv("HOST_ROOT", "/host").rstrip("/")


def enabled() -> bool:
    return os.getenv("REBUILD_ENABLED", "").strip() in ("1", "true", "yes")


def host_path(absolute: str) -> Path:
    """A host-absolute path as seen from inside this container."""
    if not HOST_ROOT or HOST_ROOT == "/":
        return Path(absolute)
    return Path(HOST_ROOT, absolute.lstrip("/"))


def target_for(labels: dict | None) -> dict | None:
    """What could be rebuilt for a container, from its Compose labels.

    ``None`` when the container wasn't started by Compose, has no working
    directory recorded, or that directory isn't a git checkout — in every
    one of those cases there is no repo to pull and no project to bring
    up.
    """
    labels = labels or {}

    project = labels.get("com.docker.compose.project")
    working_dir = labels.get("com.docker.compose.project.working_dir")

    if not project or not working_dir:
        return None

    local = host_path(working_dir)

    try:
        if not local.is_dir() or not (local / ".git").exists():
            return None
    except OSError:
        return None

    return {
        "project": project,
        "service": labels.get("com.docker.compose.service"),
        "working_dir": working_dir,
        "path": str(local),
    }


def _run(args: list[str], cwd: str, timeout: int) -> dict:
    """One step of a rebuild, captured whole. Output is what the person who
    pressed the button needs to see when it fails."""
    started = time.time()

    try:
        done = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (done.stdout or "") + (done.stderr or "")
        code = done.returncode

    except subprocess.TimeoutExpired:
        output, code = f"timed out after {timeout}s", 124
    except OSError as error:
        output, code = str(error), 127

    return {
        "command": shlex.join(args),
        "exit_code": code,
        "output": output[-8000:],
        "seconds": round(time.time() - started, 1),
    }


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
#
# A pull and build takes minutes, which is far longer than an HTTP request
# through the dashboard should be holding open. Starting one returns a job
# id straight away and the caller polls it.

_jobs: dict[str, dict] = {}
_lock = threading.Lock()

MAX_JOBS = 20


def status(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def recent() -> list[dict]:
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)
        return [dict(job) for job in jobs]


def _running() -> bool:
    return any(job["state"] == "running" for job in _jobs.values())


def _record(job: dict) -> None:
    _jobs[job["id"]] = job
    if len(_jobs) > MAX_JOBS:
        for old in sorted(_jobs.values(), key=lambda j: j["started_at"])[:-MAX_JOBS]:
            if old["state"] != "running":
                _jobs.pop(old["id"], None)


def self_project(client) -> str | None:
    """The Compose project this agent's own container belongs to, if any.

    Rebuilding that project tears down the agent, so it can't be done the
    direct way — the compose process would be killed halfway through by
    the container it is replacing.
    """
    own_id = os.getenv("HOSTNAME", "").strip()
    if not own_id:
        return None

    try:
        container = client.containers.get(own_id)
        return (container.labels or {}).get("com.docker.compose.project")
    except Exception as error:  # noqa: BLE001 - not being able to tell is fine
        log.debug("could not identify this agent's own project: %s", error)
        return None


def helper_image(client) -> str:
    """The image to run the self-rebuild in. This agent's own image by
    default: it already has git, the Docker CLI and the Compose plugin, so
    there is nothing extra to pull."""
    override = os.getenv("REBUILD_HELPER_IMAGE", "").strip()
    if override:
        return override

    own_id = os.getenv("HOSTNAME", "").strip()
    if own_id:
        try:
            container = client.containers.get(own_id)
            tags = container.image.tags
            return tags[0] if tags else container.image.id
        except Exception as error:  # noqa: BLE001
            log.debug("could not resolve this agent's image: %s", error)

    return "homelab-agent"


def start(client, target: dict, *, pull: bool = True) -> dict:
    """Kick off a rebuild. Returns the job immediately."""
    with _lock:
        if _running():
            raise RuntimeError("a rebuild is already running on this host")

        replaces_self = bool(
            target["project"]
            and target["project"] == self_project(client)
        )

        job = {
            "id": uuid.uuid4().hex[:12],
            "project": target["project"],
            "service": target.get("service"),
            "working_dir": target["working_dir"],
            "pull": pull,
            "replaces_self": replaces_self,
            "state": "running",
            "started_at": time.time(),
            "finished_at": None,
            "steps": [],
            "error": None,
        }
        _record(job)

    audit.info(
        "rebuild %s: project=%s dir=%s pull=%s%s",
        job["id"], job["project"], job["working_dir"], pull,
        " (replaces this agent)" if replaces_self else "",
    )

    thread = threading.Thread(target=_run_job, args=(client, job), daemon=True)
    thread.start()

    return dict(job)


def _finish(job: dict, state: str, error: str | None = None) -> None:
    with _lock:
        job["state"] = state
        job["error"] = error
        job["finished_at"] = time.time()

    level = audit.warning if state == "failed" else audit.info
    level("rebuild %s %s%s", job["id"], state, f": {error}" if error else "")


def _add_step(job: dict, step: dict) -> None:
    with _lock:
        job["steps"].append(step)


def _run_job(client, job: dict) -> None:
    try:
        if job["replaces_self"]:
            _hand_off(client, job)
        else:
            _rebuild_here(job)

    except Exception as error:  # noqa: BLE001 - the thread must not die silently
        _finish(job, "failed", str(error))


def _rebuild_here(job: dict) -> None:
    """The normal path: run the pull and the build ourselves."""
    path = str(host_path(job["working_dir"]))

    if job["pull"]:
        # --ff-only: a deployment checkout that has diverged from the
        # remote should stop and say so, not merge or conflict.
        step = _run(["git", "pull", "--ff-only", "origin"], path, TIMEOUT)
        _add_step(job, step)
        if step["exit_code"] != 0:
            _finish(job, "failed", "git pull failed")
            return

    step = _run(["docker", "compose", "up", "-d", "--build"], path, TIMEOUT)
    _add_step(job, step)

    if step["exit_code"] != 0:
        _finish(job, "failed", "compose up failed")
        return

    _finish(job, "done")


def _hand_off(client, job: dict) -> None:
    """The self-rebuild path.

    The agent cannot run this itself — ``compose up`` would kill the
    process doing the running. Instead a throwaway container does it, with
    the Docker socket and the project directory mounted. It outlives this
    agent by design, so the job is marked ``handed_off`` rather than
    ``done``: from here the outcome is only visible once the new agent is
    up.
    """
    working_dir = job["working_dir"]
    script = "git pull --ff-only origin && " if job["pull"] else ""
    script += "docker compose up -d --build"

    try:
        container = client.containers.run(
            helper_image(client),
            command=["sh", "-c", script],
            entrypoint="",
            detach=True,
            remove=True,
            working_dir=working_dir,
            volumes={
                "/var/run/docker.sock": {
                    "bind": "/var/run/docker.sock", "mode": "rw",
                },
                working_dir: {"bind": working_dir, "mode": "rw"},
            },
            labels={"homelab-agent-rebuild": job["id"]},
        )

    except Exception as error:  # noqa: BLE001 - docker-py raises broadly
        _finish(job, "failed", f"could not start the rebuild helper: {error}")
        return

    _add_step(job, {
        "command": f"docker run --rm {helper_image(client)} sh -c {shlex.quote(script)}",
        "exit_code": None,
        "output": (
            f"handed off to helper container {container.short_id}; this agent "
            "is about to be replaced, so the result won't appear here — watch "
            "for it coming back online"
        ),
        "seconds": 0.0,
    })

    _finish(job, "handed_off")


def summary_for(labels: dict | None) -> dict | None:
    """What ``GET /containers`` carries per container, so the dashboard
    knows where a Rebuild button belongs without asking twice."""
    if not enabled():
        return None

    target = target_for(labels)
    if target is None:
        return None

    return {"project": target["project"], "service": target.get("service")}
