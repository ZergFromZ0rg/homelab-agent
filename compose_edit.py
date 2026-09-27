"""Container settings: edit the compose file, not the container.

Changing a running container directly gets undone by the next
``docker compose up``, so the dashboard edits the file Compose reads and
then has Compose apply it. The labels Compose puts on every container say
which project, service, folder and files — nothing to configure.

Three steps, each its own route:

- **read** — the project's compose files, which one defines the service,
  and whether this host allows applying.
- **preview** — ``docker compose config`` on the edited text plus a diff.
  The new text is checked from a copy inside a helper container, with the
  real project folder as ``--project-directory``, so ``./data`` and
  ``.env`` resolve exactly as they will for real and nothing on the host
  is touched until you apply.
- **apply** — a job: save the file (as its owner, like the file browser),
  ``docker compose up -d`` in a helper at the project's real path, then
  watch the project's containers. A container that exits non-zero,
  restart-loops or turns unhealthy inside the watch window rolls the file
  back and runs ``up -d`` again, and the job says which container and
  shows its last log lines.

Applying runs whatever the file says, as root — the same class of thing as
a rebuild — so it needs ``REBUILD_ENABLED``. The agent's own project is
refused: ``up`` would replace this process halfway through the job.

Containers not started by Compose get a read-only summary and a generated
compose file to start from (``generate``); switching one over is manual.
"""

from __future__ import annotations

import difflib
import io
import os
import posixpath
import tarfile
import threading
import time
import uuid

import yaml

import files
import rebuild
from disk_usage import DiskUsageError
from log import audit, log

HELPER_TIMEOUT = 900
WATCH_SECONDS = int(os.getenv("COMPOSE_WATCH_SECONDS", "45"))
HEALTH_GRACE_SECONDS = 120
MAX_JOBS = 20

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


class NotCompose(DiskUsageError):
    """A container Compose didn't start."""


# --- where things are --------------------------------------------------------


def target(client, container_id: str) -> dict:
    container = client.containers.get(container_id)
    labels = container.labels or {}
    project = labels.get("com.docker.compose.project")
    working_dir = labels.get("com.docker.compose.project.working_dir")
    if not project or not working_dir:
        raise NotCompose(f"{container.name} wasn't started by Compose")
    config_files = [
        f.strip() for f in (labels.get("com.docker.compose.project.config_files") or "").split(",")
        if f.strip()
    ] or [posixpath.join(working_dir, "compose.yml")]
    return {
        "container": container.name,
        "project": project,
        "service": labels.get("com.docker.compose.service"),
        "working_dir": working_dir,
        "files": config_files,
    }


def _read(path: str) -> tuple[str, float]:
    with open(files.disk_usage._on_host(path), encoding="utf-8") as f:
        content = f.read()
    return content, os.stat(files.disk_usage._on_host(path)).st_mtime


def _defines(content: str, service: str | None) -> bool:
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return False
    return isinstance(data, dict) and service in (data.get("services") or {})


def why_not_apply(client, info: dict) -> str | None:
    if not rebuild.enabled():
        return "this host doesn't allow compose changes — turn on 'Allow rebuilds and compose changes' for it"
    if info["project"] == rebuild.self_project(client):
        return "this is the agent's own stack — applying would stop the agent halfway through"
    return None


def read(client, container_id: str, owner_uid: int | None) -> dict:
    info = target(client, container_id)
    roots = files.write_roots(client, owner_uid)
    out = []
    for path in info["files"]:
        try:
            content, modified = _read(path)
        except OSError as error:
            out.append({"path": path, "error": f"can't read it: {error.strerror or error}"})
            continue
        out.append({
            "path": path,
            "content": content,
            "modified": modified,
            "defines_service": _defines(content, info["service"]),
            "writable": files.why_not_writable(path, roots) is None,
        })
    return {**info, "files": out, "can_apply": why_not_apply(client, info) is None,
            "why_not": why_not_apply(client, info)}


# --- checking -----------------------------------------------------------------


def _compose_args(info: dict, edited: str, replacement: str) -> list[str]:
    args = ["docker", "compose", "-p", info["project"], "--project-directory", info["working_dir"]]
    for path in info["files"]:
        args += ["-f", replacement if path == edited else path]
    return args


def _mounts(info: dict, *, socket: bool) -> dict:
    folders = {info["working_dir"]} | {posixpath.dirname(f) for f in info["files"]}
    mounts = {d: {"bind": d, "mode": "ro"} for d in folders}
    if socket:
        mounts["/var/run/docker.sock"] = {"bind": "/var/run/docker.sock", "mode": "rw"}
    return mounts


def _tar_one(name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        info.mtime = time.time()
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _run_helper(client, command: list[str], mounts: dict, *, put: tuple[str, bytes] | None = None,
                network: bool = False) -> tuple[int, str]:
    container = client.containers.create(
        rebuild.helper_image(client),
        command=command,
        volumes=mounts,
        network_disabled=not network,
        labels={"homelab-agent-compose": "1"},
    )
    try:
        if put:
            container.put_archive("/tmp", _tar_one(*put))
        container.start()
        result = container.wait(timeout=HELPER_TIMEOUT)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        return code, container.logs().decode("utf-8", "replace").strip()
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def _check(client, info: dict, path: str, content: str) -> str | None:
    """None if Compose accepts the project with ``content`` as ``path``."""
    code, output = _run_helper(
        client,
        _compose_args(info, path, "/tmp/hl-check.yml") + ["config", "-q"],
        _mounts(info, socket=False),
        put=("hl-check.yml", content.encode("utf-8")),
    )
    if code == 0:
        return None
    return output.replace("/tmp/hl-check.yml", posixpath.basename(path))[-1500:] or f"compose config exited {code}"


def _edited(info: dict, path: str) -> str:
    if path not in info["files"]:
        raise DiskUsageError(f"{path} isn't one of this project's compose files")
    return path


def preview(client, container_id: str, path: str, content: str) -> dict:
    info = target(client, container_id)
    path = _edited(info, path)
    old, _ = _read(path)
    diff = "".join(difflib.unified_diff(
        old.splitlines(keepends=True), content.splitlines(keepends=True),
        fromfile=posixpath.basename(path), tofile=posixpath.basename(path),
    ))
    return {"valid": (error := _check(client, info, path, content)) is None,
            "error": error, "diff": diff, "changed": old != content}


# --- applying -----------------------------------------------------------------


def _state(container) -> dict:
    state = container.attrs.get("State") or {}
    return {
        "name": container.name,
        "status": state.get("Status"),
        "exit_code": state.get("ExitCode"),
        "health": (state.get("Health") or {}).get("Status"),
        "restarts": container.attrs.get("RestartCount", 0),
    }


def _project_containers(client, project: str):
    return client.containers.list(
        all=True, filters={"label": f"com.docker.compose.project={project}"}
    )


def watch(client, project: str, *, seconds: int | None = None, sleep=time.sleep,
          clock=time.monotonic) -> dict | None:
    """Watch a project after ``up``. Returns the first container that went
    wrong (with why), or None if everything stayed up for ``seconds`` and
    anything with a healthcheck reported healthy."""
    seconds = WATCH_SECONDS if seconds is None else seconds
    start = clock()
    baseline: dict[str, int] = {}
    while True:
        waiting_on_health = False
        for container in _project_containers(client, project):
            try:
                container.reload()
            except Exception:  # noqa: BLE001 - gone between list and reload
                continue
            s = _state(container)
            baseline.setdefault(s["name"], s["restarts"])
            if s["status"] in ("dead", "restarting") or s["restarts"] > baseline[s["name"]]:
                return {**s, "why": "keeps restarting"}
            if s["status"] == "exited" and s["exit_code"] not in (0, None):
                return {**s, "why": f"exited with code {s['exit_code']}"}
            if s["health"] == "unhealthy":
                return {**s, "why": "is unhealthy"}
            if s["health"] == "starting":
                waiting_on_health = True
        elapsed = clock() - start
        if elapsed >= seconds and not waiting_on_health:
            return None
        if elapsed >= seconds + HEALTH_GRACE_SECONDS:
            return {"name": project, "why": "a healthcheck never passed", "status": "starting"}
        sleep(3)


def status(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job, steps=list(job["steps"])) if job else None


def _step(job: dict, text: str, output: str | None = None) -> None:
    with _lock:
        job["steps"].append({"at": time.time(), "text": text, "output": output})


def _finish(job: dict, state: str, error: str | None = None) -> None:
    with _lock:
        job["state"] = state
        job["error"] = error
        job["finished_at"] = time.time()


def start(client, container_id: str, path: str, content: str, modified: float | None,
          owner_uid: int | None) -> dict:
    info = target(client, container_id)
    path = _edited(info, path)
    reason = why_not_apply(client, info)
    if reason:
        raise DiskUsageError(reason)
    with _lock:
        if any(j["state"] == "running" and j["project"] == info["project"] for j in _jobs.values()):
            raise files.Conflict(f"a change to {info['project']} is already being applied")
        job = {
            "id": uuid.uuid4().hex[:12], "project": info["project"], "path": path,
            "state": "running", "error": None, "steps": [],
            "started_at": time.time(), "finished_at": None, "failed": None,
        }
        _jobs[job["id"]] = job
        for old in sorted(_jobs.values(), key=lambda j: j["started_at"])[:-MAX_JOBS]:
            if old["state"] != "running":
                _jobs.pop(old["id"], None)
    threading.Thread(
        target=_apply, args=(client, job, info, content, modified, owner_uid), daemon=True
    ).start()
    return status(job["id"])


def _up(client, info: dict) -> tuple[int, str]:
    # Network on: `up` may have to pull a new image.
    return _run_helper(client, _compose_args(info, "", "") + ["up", "-d"],
                       _mounts(info, socket=True), network=True)


def _logs(client, name: str) -> str:
    try:
        return client.containers.get(name).logs(tail=40).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _write(client, path: str, content: str, owner_uid, *, modified) -> None:
    data = content.encode("utf-8")
    files.write_file(client, path, io.BytesIO(data), len(data), owner_uid,
                     overwrite=True, expected_modified=modified)


def _apply(client, job, info, content, modified, owner_uid) -> None:
    path = job["path"]
    try:
        error = _check(client, info, path, content)
        if error:
            return _finish(job, "failed", f"Compose rejected it:\n{error}")
        previous, _ = _read(path)

        _write(client, path, content, owner_uid, modified=modified)
        _step(job, f"saved {posixpath.basename(path)}")
        audit.info("compose: applying %s (%s)", info["project"], path)

        code, output = _up(client, info)
        _step(job, "docker compose up -d", output[-3000:])
        failed = (
            {"name": info["project"], "why": f"docker compose up failed (exit {code})"}
            if code != 0 else None
        )
        if failed is None:
            _step(job, f"watching for {WATCH_SECONDS}s")
            failed = watch(client, info["project"])

        if failed is None:
            _step(job, "all containers up")
            audit.info("compose: applied %s", info["project"])
            return _finish(job, "done")

        with _lock:
            job["failed"] = {**failed, "logs": _logs(client, failed["name"])}
        _step(job, f"{failed['name']} {failed['why']} — rolling back")
        _write(client, path, previous, owner_uid, modified=None)
        code, output = _up(client, info)
        _step(job, "restored the previous file and ran up -d again", output[-3000:])
        audit.warning("compose: rolled back %s: %s %s", info["project"], failed["name"], failed["why"])
        _finish(job, "rolled_back", f"{failed['name']} {failed['why']}; the previous file is back")
    except files.Conflict as error:
        _finish(job, "failed", str(error))
    except Exception as error:  # noqa: BLE001 - reported to the user
        log.exception("compose apply failed")
        _finish(job, "failed", str(error))


# --- containers Compose didn't start -----------------------------------------


class _Quoted(str):
    """Printed in double quotes: "8080:80", as Compose's docs advise —
    YAML 1.1 reads an unquoted 80:80 as a base-60 number."""


class _Dumper(yaml.SafeDumper):
    """Lists indented under their key, the way compose files are written."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


_Dumper.add_representer(
    _Quoted, lambda dumper, value: dumper.represent_scalar("tag:yaml.org,2002:str", value, style='"')
)


def generate(client, container_id: str) -> dict:
    """A compose file that would recreate this container, as a start."""
    container = client.containers.get(container_id)
    attrs = container.attrs
    config = attrs.get("Config") or {}
    host = attrs.get("HostConfig") or {}
    image_env: set[str] = set()
    image_cmd = None
    try:
        image = client.images.get(config.get("Image") or container.image.id)
        image_env = set((image.attrs.get("Config") or {}).get("Env") or [])
        image_cmd = (image.attrs.get("Config") or {}).get("Cmd")
    except Exception:  # noqa: BLE001
        pass

    service: dict = {"image": config.get("Image"), "container_name": container.name}
    restart = (host.get("RestartPolicy") or {}).get("Name")
    if restart and restart != "no":
        service["restart"] = restart
    if host.get("NetworkMode") in ("host", "none"):
        service["network_mode"] = host["NetworkMode"]
    if host.get("PidMode"):
        service["pid"] = host["PidMode"]
    if host.get("Privileged"):
        service["privileged"] = True
    if host.get("CapAdd"):
        service["cap_add"] = host["CapAdd"]
    ports = []
    for private, bindings in (host.get("PortBindings") or {}).items():
        for b in bindings or []:
            ip = f"{b['HostIp']}:" if b.get("HostIp") not in ("", "0.0.0.0", None) else ""
            number, proto = private.split("/")
            ports.append(f"{ip}{b.get('HostPort')}:{number}" + ("" if proto == "tcp" else f"/{proto}"))
    if ports:
        service["ports"] = [_Quoted(p) for p in ports]
    volumes = list(host.get("Binds") or [])
    volumes += [
        f"{m['Name']}:{m['Destination']}" for m in attrs.get("Mounts") or []
        if m.get("Type") == "volume" and m.get("Name") and len(m["Name"]) != 64
    ]
    if volumes:
        service["volumes"] = volumes
    env = [e for e in config.get("Env") or [] if e not in image_env]
    if env:
        service["environment"] = env
    if config.get("Cmd") and config.get("Cmd") != image_cmd:
        service["command"] = config["Cmd"]
    if host.get("Devices"):
        service["devices"] = [f"{d['PathOnHost']}:{d['PathInContainer']}" for d in host["Devices"]]

    text = yaml.dump({"services": {container.name: service}}, Dumper=_Dumper, sort_keys=False, width=100)
    return {"container": container.name, "compose": False, "generated": text,
            "suggested_path": f"~/docker/stacks/{container.name}/compose.yml"}
