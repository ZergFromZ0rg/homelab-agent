"""Run a Compose project from YAML the dashboard scheduler sends.

The dashboard picks the host; this writes the compose file to
``STACK_DIR/<name>/`` and runs ``docker compose`` against the host daemon.

Compose has dozens of keys, several of which hand a container the host
(``privileged``, ``security_opt``, host namespaces, socket mounts, bind
volumes disguised as named volumes, ``volumes_from``). Rather than
blocklist them, ``check_stack_policy`` walks the file against an
**allowlist** of service keys and inspects volumes / devices / registries
against the same ALLOWED_* config as ``deploy.py``. Anything unrecognised
is rejected.

Env knobs:
  STACK_DIR               where project files live (default /data/stacks)
  STACK_COMPOSE_TIMEOUT   seconds for a compose up/down (default 900)
  ALLOWED_REGISTRIES / ALLOWED_HOST_PATHS / ALLOWED_DEVICES  see deploy.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

import deploy
from deploy import PolicyError, valid_name

STACK_DIR = Path(os.getenv("STACK_DIR", "/data/stacks"))
COMPOSE_TIMEOUT = int(os.getenv("STACK_COMPOSE_TIMEOUT", "900"))

# Service keys the agent understands and considers safe. Everything a
# normal self-hosted app needs; nothing that reaches outside the container.
_ALLOWED_SERVICE_KEYS = {
    "image", "container_name", "command", "entrypoint", "environment",
    "env_file", "ports", "expose", "volumes", "restart", "deploy",
    "depends_on", "healthcheck", "labels", "networks", "hostname",
    "domainname", "working_dir", "user", "tmpfs", "stop_grace_period",
    "stop_signal", "init", "read_only", "shm_size", "logging", "profiles",
    "pull_policy", "platform", "cap_drop", "security_opt", "devices",
    "mem_limit", "memswap_limit", "mem_reservation", "cpus", "cpu_shares",
    "pids_limit", "oom_score_adj", "ulimits", "dns", "labels",
}
_ALLOWED_TOP_KEYS = {"services", "volumes", "networks", "name", "version", "configs"}

# security_opt values that don't weaken isolation.
_SAFE_SECURITY_OPT_PREFIXES = ("no-new-privileges",)

_MAX_SERVICES = 50


class CreateStackRequest(BaseModel):
    name: str = Field(min_length=1, max_length=63)
    compose_yaml: str = Field(min_length=1, max_length=512_000)
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip().lower()
        return valid_name(value)


def _volume_defs_are_binds(doc: dict) -> set[str]:
    """Named-volume definitions that are really host bind mounts — the classic
    way to smuggle ``/`` past a service-level volume check:

        volumes:
          sneaky: {driver_opts: {type: none, o: bind, device: /}}
    """
    binds: dict[str, str] = {}
    for vname, vdef in (doc.get("volumes") or {}).items():
        if not isinstance(vdef, dict):
            continue
        opts = vdef.get("driver_opts") or {}
        o = str(opts.get("o") or "")
        device = opts.get("device")
        if device and ("bind" in o or str(opts.get("type")) == "none"):
            binds[str(vname)] = str(device)
    return binds


def _service_volume_sources(service: dict) -> list[str]:
    out: list[str] = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, dict):
            if entry.get("source"):
                out.append(str(entry["source"]))
        else:
            out.append(str(entry).split(":")[0])
    return out


def _reject_namespace(service: dict, sname: str) -> None:
    for key in ("network_mode", "pid", "ipc", "uts", "cgroup"):
        value = str(service.get(key) or "")
        if not value:
            continue
        if value in ("host",) or value.startswith(("container:", "service:")):
            raise PolicyError(f"service {sname!r}: {key}: {value!r} is not allowed")
    if str(service.get("userns_mode") or "") == "host":
        raise PolicyError(f"service {sname!r}: userns_mode: host is not allowed")
    if service.get("privileged"):
        raise PolicyError(f"service {sname!r}: privileged is not allowed")
    for key in ("cap_add", "device_cgroup_rules", "volumes_from", "extra_hosts", "group_add"):
        if service.get(key):
            raise PolicyError(f"service {sname!r}: {key} is not allowed")


def check_stack_policy(doc: dict, name: str) -> None:
    if name in deploy.PROTECTED_NAMES:
        raise PolicyError(f"{name!r} is a protected project name")

    stray_top = set(doc) - _ALLOWED_TOP_KEYS - {k for k in doc if str(k).startswith("x-")}
    if stray_top:
        raise PolicyError(f"unsupported top-level compose key(s): {', '.join(sorted(stray_top))}")

    bind_volumes = _volume_defs_are_binds(doc)
    for vname, device in bind_volumes.items():
        if not deploy.host_path_allowed(device):
            raise PolicyError(
                f"volume {vname!r} bind-mounts {device!r}, which is not under "
                f"ALLOWED_HOST_PATHS"
            )

    services = doc.get("services") or {}
    if not services:
        raise PolicyError("compose file defines no services")
    if len(services) > _MAX_SERVICES:
        raise PolicyError(f"too many services (max {_MAX_SERVICES})")

    for sname, raw in services.items():
        service = raw if isinstance(raw, dict) else {}

        if "build" in service:
            raise PolicyError(
                f"service {sname!r} uses build: — push a pre-built image instead"
            )

        stray = set(service) - _ALLOWED_SERVICE_KEYS - {
            k for k in service if str(k).startswith("x-")
        }
        if stray:
            raise PolicyError(
                f"service {sname!r}: unsupported compose key(s): {', '.join(sorted(stray))}"
            )

        _reject_namespace(service, sname)

        for opt in service.get("security_opt") or []:
            if not str(opt).startswith(_SAFE_SECURITY_OPT_PREFIXES):
                raise PolicyError(
                    f"service {sname!r}: security_opt {opt!r} is not allowed"
                )

        for dev in service.get("devices") or []:
            if not deploy.device_allowed(str(dev)):
                raise PolicyError(
                    f"service {sname!r}: device {dev!r} is not in ALLOWED_DEVICES"
                )

        image = service.get("image")
        if image:
            deploy.check_registry(str(image), where=f"service {sname!r}")

        for source in _service_volume_sources(service):
            if source in bind_volumes:
                continue  # already validated as a named-but-bind volume above
            if deploy.looks_like_host_path(source) and not deploy.host_path_allowed(source):
                raise PolicyError(
                    f"service {sname!r}: bind mount {source!r} is not under "
                    f"ALLOWED_HOST_PATHS — use a named volume"
                )

        for key in service.get("labels") or {}:
            if str(key).startswith("com.docker."):
                raise PolicyError(
                    f"service {sname!r}: label {key!r} is reserved"
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
        env_path.write_text("".join(f"{k}={v}\n" for k, v in request.env.items()))
    elif env_path.exists():
        env_path.unlink()

    try:
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
    name = valid_name((name or "").strip().lower())
    if name in deploy.PROTECTED_NAMES:
        raise PolicyError(f"{name!r} is a protected project name")

    project_dir = STACK_DIR / name
    args = ["-p", name, "down", "--remove-orphans"]
    if volumes:
        args.append("--volumes")

    cwd = project_dir if (project_dir / "docker-compose.yml").exists() else STACK_DIR
    try:
        result = _compose(args, cwd)
    except subprocess.TimeoutExpired:
        raise PolicyError("compose down timed out", stage="create")

    # Only ever remove a directory that is a direct child of STACK_DIR.
    if project_dir.parent == STACK_DIR and project_dir != STACK_DIR:
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
