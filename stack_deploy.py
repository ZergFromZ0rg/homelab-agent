"""Run a Compose project from YAML the dashboard scheduler sends.

The dashboard picks the host; this writes the compose file to
``STACK_DIR/<name>/`` and runs ``docker compose`` against the host daemon
(the agent already has the socket; the image ships the compose plugin).

Same conservative stance as ``deploy.py``: ``check_stack_policy`` walks
every service and rejects privileged/host-namespace/socket/out-of-allowlist
things before compose is invoked. ``build:`` is refused outright — the
agent has no build context.

Env knobs:
  STACK_DIR               where project files live (default /data/stacks)
  STACK_COMPOSE_TIMEOUT   seconds for a compose up/down (default 900)
  ALLOWED_REGISTRIES / ALLOWED_HOST_PATHS  shared with deploy.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

import deploy
from deploy import PolicyError

STACK_DIR = Path(os.getenv("STACK_DIR", "/data/stacks"))
COMPOSE_TIMEOUT = int(os.getenv("STACK_COMPOSE_TIMEOUT", "900"))
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

_BANNED_SERVICE_KEYS = ("privileged", "cap_add", "devices", "device_cgroup_rules")


class CreateStackRequest(BaseModel):
    name: str
    compose_yaml: str = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip().lower()
        if not NAME_RE.match(value):
            raise ValueError("name must be lowercase [a-z0-9_-]")
        return value


def _volume_sources(service: dict) -> list[str]:
    out: list[str] = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, dict):
            if entry.get("source"):
                out.append(str(entry["source"]))
        else:
            out.append(str(entry).split(":")[0])
    return out


def check_stack_policy(doc: dict, name: str) -> None:
    if name in deploy.PROTECTED_NAMES:
        raise PolicyError(f"{name!r} is a protected project name")

    services = doc.get("services") or {}
    for sname, raw in services.items():
        service = raw or {}

        if service.get("build"):
            raise PolicyError(
                f"service {sname!r} uses build: — push a pre-built image instead",
            )

        for key in _BANNED_SERVICE_KEYS:
            if service.get(key):
                raise PolicyError(f"service {sname!r}: {key} is not allowed")

        net = str(service.get("network_mode") or "")
        if net == "host" or net.startswith("container:"):
            raise PolicyError(f"service {sname!r}: network_mode {net!r} not allowed")
        if service.get("pid") == "host":
            raise PolicyError(f"service {sname!r}: pid: host not allowed")

        image = service.get("image")
        if image and deploy.ALLOWED_REGISTRIES:
            registry = deploy._image_registry(image)
            if registry not in deploy.ALLOWED_REGISTRIES:
                raise PolicyError(
                    f"service {sname!r}: image registry {registry!r} not in "
                    f"ALLOWED_REGISTRIES"
                )

        for source in _volume_sources(service):
            if source.startswith((".", "/", "~")) and not deploy._host_path_allowed(
                source
            ):
                raise PolicyError(
                    f"service {sname!r}: bind mount {source!r} is not under "
                    f"ALLOWED_HOST_PATHS — use a named volume"
                )


def _tail(text: str, lines: int = 12) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _project_services(client, name: str) -> list[dict]:
    containers = client.containers.list(
        all=True,
        filters={"label": f"com.docker.compose.project={name}"},
    )
    return [
        {"name": c.name, "id": c.short_id, "status": c.status}
        for c in sorted(containers, key=lambda c: c.name)
    ]


def _compose(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=COMPOSE_TIMEOUT,
        check=False,
    )


def deploy_stack(client, request: CreateStackRequest) -> dict:
    try:
        doc = yaml.safe_load(request.compose_yaml)
    except yaml.YAMLError as error:
        raise PolicyError(f"invalid compose YAML: {error}", stage="policy")

    if not isinstance(doc, dict) or not (doc.get("services") or {}):
        raise PolicyError("compose file defines no services", stage="policy")

    check_stack_policy(doc, request.name)

    project_dir = STACK_DIR / request.name
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "docker-compose.yml").write_text(request.compose_yaml)

    env_path = project_dir / ".env"
    if request.env:
        env_path.write_text(
            "".join(f"{k}={v}\n" for k, v in request.env.items())
        )
    elif env_path.exists():
        env_path.unlink()

    try:
        # --pull missing: pull images we don't have, but don't re-check the
        # registry for every already-cached image on every deploy (that
        # turns a redeploy of a cached stack into a multi-minute wait).
        result = _compose(
            ["-p", request.name, "up", "-d", "--remove-orphans", "--pull", "missing"],
            project_dir,
        )
    except subprocess.TimeoutExpired:
        raise PolicyError("compose up timed out", stage="create")
    except FileNotFoundError:
        raise PolicyError(
            "docker compose is not installed in this agent image", stage="create"
        )

    if result.returncode != 0:
        raise PolicyError(_tail(result.stderr or result.stdout), stage="create")

    return {
        "success": True,
        "project": request.name,
        "services": _project_services(client, request.name),
    }


def remove_stack(client, name: str, *, volumes: bool = False) -> dict:
    name = name.strip().lower()
    if name in deploy.PROTECTED_NAMES:
        raise PolicyError(f"{name!r} is a protected project name")

    project_dir = STACK_DIR / name
    args = ["-p", name, "down", "--remove-orphans"]
    if volumes:
        args.append("--volumes")

    cwd = project_dir if (project_dir / "docker-compose.yml").exists() else Path.cwd()
    try:
        result = _compose(args, cwd)
    except subprocess.TimeoutExpired:
        raise PolicyError("compose down timed out", stage="create")

    shutil.rmtree(project_dir, ignore_errors=True)

    if result.returncode != 0:
        return {"success": False, "project": name, "error": _tail(result.stderr)}
    return {"success": True, "project": name, "action": "down"}


def list_stacks(client) -> list[dict]:
    """Compose projects that have at least one container on this host."""
    projects: dict[str, list[dict]] = {}
    for container in client.containers.list(all=True):
        project = (container.labels or {}).get("com.docker.compose.project")
        if not project:
            continue
        projects.setdefault(project, []).append(
            {"name": container.name, "id": container.short_id, "status": container.status}
        )
    return [
        {"project": name, "services": sorted(svcs, key=lambda s: s["name"])}
        for name, svcs in sorted(projects.items())
    ]
