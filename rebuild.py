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
  REBUILD_TIMEOUT       seconds to wait for a rebuild (default 1800).
  REBUILD_HELPER_IMAGE  image for the self-rebuild helper below; defaults
                        to this agent's own image, which already carries
                        git, the Docker CLI and the Compose plugin.
"""

from __future__ import annotations

import os
import re
import shlex
import threading
import time
import uuid
from pathlib import Path

import config
from log import audit, log

TIMEOUT = int(os.getenv("REBUILD_TIMEOUT", "1800"))

# Where the host filesystem is mounted, so a label's absolute path can be
# read from in here. Same knob the backup worker uses.
HOST_ROOT = os.getenv("HOST_ROOT", "/host").rstrip("/")


def enabled() -> bool:
    return config.get("REBUILD_ENABLED").strip().lower() in ("1", "true", "yes")


def host_path(absolute: str) -> Path:
    """A host-absolute path as seen from inside this container."""
    if not HOST_ROOT or HOST_ROOT == "/":
        return Path(absolute)
    return Path(HOST_ROOT, absolute.lstrip("/"))


# The helper has git and CA certificates. It does not have an ssh binary,
# or any of the host user's keys — nor should it: this is an
# unauthenticated read of a public repo, and handing a container someone's
# signing key to do it would be absurd.
#
# So an ssh remote isn't a problem to be fixed on the host. ssh is the
# right way for a person to push; it just isn't available in here. The
# same repo is readable over https, and the URL for it is derivable, so
# that's what gets fetched. Nothing on the host changes and pushes keep
# using the keys they always did.
PULLABLE_SCHEMES = ("http://", "https://")

_SSH_URL = re.compile(r"^(?:ssh://)?(?:[^@/]+@)?([^:/]+)[:/](.+?)(?:\.git)?/?$")


def https_equivalent(url: str | None) -> str | None:
    """The https URL for the same repo, for anything ssh-shaped.

    ``git@github.com:owner/repo.git`` and ``ssh://git@github.com/owner/repo``
    both become ``https://github.com/owner/repo.git``. An https URL is
    returned unchanged. Anything else — a local path, a protocol we don't
    recognise — gets None rather than a guess.
    """
    if not url:
        return None

    lowered = url.lower()

    if lowered.startswith(PULLABLE_SCHEMES):
        return url

    if not (lowered.startswith("ssh://") or "@" in url.split("/")[0]):
        return None

    match = _SSH_URL.match(url)
    if not match:
        return None

    host, path = match.groups()
    return f"https://{host}/{path}.git"


def origin_url(git_dir: Path) -> str | None:
    """The origin remote from a checkout's config, read directly so this
    works without shelling out to git."""
    try:
        config = (git_dir / "config").read_text(errors="replace")
    except OSError:
        return None

    in_origin = False

    for line in config.splitlines():
        stripped = line.strip()

        if stripped.startswith("["):
            in_origin = stripped.replace(" ", "").lower() == '[remote"origin"]'
            continue

        if in_origin and stripped.lower().startswith("url"):
            _, _, value = stripped.partition("=")
            return value.strip() or None

    return None


def can_pull(url: str | None) -> bool:
    """Whether the helper can fetch this repo at all — directly or by
    deriving the https URL for it."""
    return https_equivalent(url) is not None


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

    remote = origin_url(local / ".git")

    return {
        "project": project,
        "service": labels.get("com.docker.compose.service"),
        "working_dir": working_dir,
        "path": str(local),
        "remote": remote,
        # What the helper will actually fetch from, which is not always
        # what's configured: an ssh remote is read over https instead.
        "fetch_url": https_equivalent(remote),
        "can_pull": can_pull(remote),
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
    if pull and not target.get("can_pull", True):
        raise ValueError(
            f"can't pull {target['project']}: its origin is "
            f"{target.get('remote') or 'not set'}, which isn't a URL the "
            "helper can fetch over http(s). Rebuild without pulling, or "
            "point the remote at a reachable repo."
        )

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
            "fetch_url": target.get("fetch_url"),
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


def _script(job: dict) -> str:
    """The shell the helper runs.

    ``safe.directory`` is not optional: the checkout belongs to whoever
    owns it on the host, this runs as root, and git has refused to touch a
    repo owned by another user since 2.35.2. Without it every pull fails
    with "detected dubious ownership" before anything is fetched.

    ``--ff-only`` so a checkout that has diverged from its remote stops
    and says so rather than merging or leaving conflicts behind.
    """
    parts = []

    if job["pull"]:
        quoted = shlex.quote(job["working_dir"])
        safe = f"git -c safe.directory={quoted}"
        url = shlex.quote(job["fetch_url"])
        # Pull from the URL by name rather than from "origin", so a remote
        # configured for ssh push is still fetched over https in here.
        parts.append(f'{safe} pull --ff-only {url} "$({safe} rev-parse --abbrev-ref HEAD)"')

    parts.append("docker compose up -d --build")

    return " && ".join(parts)


# Git and compose both fail in a handful of recognisable ways, and their
# own wording tends to describe the symptom rather than the cause. "could
# not read Username for https://github.com" is a private repo; nothing in
# that sentence says so.
#
# Ordered: the first pattern that matches wins, so put the specific ones
# before the general.
_FAILURES = (
    (
        ("could not read username", "authentication failed", "invalid username or password"),
        "that repo is private, and the agent has no credentials for it. "
        "Pull it on the host yourself, then rebuild without pulling.",
    ),
    (
        ("permission denied (publickey", "host key verification failed"),
        "the remote refused the agent's (nonexistent) ssh key. A public "
        "repo is read over https instead; a private one needs pulling on "
        "the host.",
    ),
    (
        ("dubious ownership",),
        "git refused the checkout's ownership — this is a bug in the agent, "
        "not your setup; it should be passing -c safe.directory.",
    ),
    (
        ("not possible to fast-forward", "diverging branches", "would be overwritten"),
        "the checkout on that host has diverged from the remote, so a "
        "fast-forward pull won't work. Sort it out there — the agent won't "
        "merge or discard anything on its own.",
    ),
    (
        ("could not resolve host", "unable to access", "connection timed out",
         "network is unreachable"),
        "the host couldn't reach the git remote.",
    ),
    (
        ("no space left on device",),
        "that host is out of disk space.",
    ),
    (
        ("port is already allocated", "address already in use"),
        "a port the project wants is already taken on that host.",
    ),
    (
        ("pull access denied", "manifest unknown", "not found: manifest"),
        "an image in the project couldn't be pulled — check the tag exists "
        "and the registry is reachable.",
    ),
)


def classify_failure(output: str, exit_code: int) -> str:
    """Turn a build's output into something worth reading.

    Falls back to the exit code rather than inventing a cause: a wrong
    explanation is worse than none.
    """
    lowered = (output or "").lower()

    for needles, message in _FAILURES:
        if any(needle in lowered for needle in needles):
            return message

    return f"rebuild exited {exit_code}"


def _run_job(client, job: dict) -> None:
    try:
        _rebuild(client, job)
    except Exception as error:  # noqa: BLE001 - the thread must not die silently
        _finish(job, "failed", str(error))


def _rebuild(client, job: dict) -> None:
    """Every rebuild goes through a throwaway container, including the
    ones that don't replace this agent.

    Doing the ordinary ones here instead looks simpler and is wrong. The
    agent sees the host filesystem under ``HOST_ROOT``, so it would run
    compose from ``/host/srv/thing`` while the daemon it is talking to
    knows that project as ``/srv/thing``. Compose resolves a service's
    relative bind mounts against the directory it was run from, so
    ``./data:/data`` would be handed to the daemon as ``/host/srv/thing/
    data`` — a path that doesn't exist on the host, which Docker would
    then helpfully create as an empty directory. The containers come up
    with empty volumes and nothing reports an error.

    The helper has the project bind-mounted at its real path, so every
    path resolves exactly as it would in a shell on the host.
    """
    script = _script(job)
    working_dir = job["working_dir"]
    started = time.time()

    try:
        container = client.containers.run(
            helper_image(client),
            command=["sh", "-c", script],
            detach=True,
            # A self-rebuild kills this agent before it can clean up, so
            # that one removes itself. For the rest we come back for the
            # exit code and the log first.
            auto_remove=job["replaces_self"],
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

    if job["replaces_self"]:
        _add_step(job, {
            "command": script,
            "exit_code": None,
            "output": (
                f"handed off to helper container {container.short_id}; this "
                "agent is about to be replaced, so the result won't appear "
                "here — watch for it coming back online"
            ),
            "seconds": round(time.time() - started, 1),
        })
        _finish(job, "handed_off")
        return

    try:
        result = container.wait(timeout=TIMEOUT)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        output = container.logs().decode("utf-8", "replace")

    except Exception as error:  # noqa: BLE001
        _finish(job, "failed", f"lost track of the rebuild helper: {error}")
        return

    finally:
        try:
            container.remove(force=True)
        except Exception as error:  # noqa: BLE001 - best effort
            log.debug("could not remove rebuild helper: %s", error)

    _add_step(job, {
        "command": script,
        "exit_code": code,
        "output": output[-8000:],
        "seconds": round(time.time() - started, 1),
    })

    _finish(
        job,
        "done" if code == 0 else "failed",
        None if code == 0 else classify_failure(output, code),
    )


def summary_for(labels: dict | None) -> dict | None:
    """What ``GET /containers`` carries per container, so the dashboard
    knows where a Rebuild button belongs without asking twice."""
    if not enabled():
        return None

    target = target_for(labels)
    if target is None:
        return None

    return {
        "project": target["project"],
        "service": target.get("service"),
        "remote": target["remote"],
        # False for an ssh remote: the helper has no ssh binary and none of
        # your keys, so a pull would fail before reaching the network. The
        # dashboard uses this to ask for a build without a pull rather than
        # offering one that can't work.
        "can_pull": target["can_pull"],
    }
