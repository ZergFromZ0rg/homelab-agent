"""Create and run a container from a spec sent by the dashboard scheduler.

The dashboard decides *where* a container goes; this module is the *how* on
the chosen host. It is deliberately conservative — the request model only
exposes image / env / ports / volumes / restart policy / resource limits,
and ``check_policy`` rejects anything outside a configurable allowlist
before Docker is touched. That policy is the real containment boundary:
the dashboard is a semi-trusted caller once it can create containers.

Env knobs (all optional):
  ALLOWED_REGISTRIES   comma list, e.g. "lscr.io,docker.io,ghcr.io".
                       Empty = allow any registry.
  ALLOWED_HOST_PATHS   comma list of host path prefixes that may be
                       bind-mounted. Empty = named volumes only.
  DEPLOY_PULL_TIMEOUT  seconds to allow for an image pull (default 600).
"""

from __future__ import annotations

import os
from typing import Literal

import docker
from pydantic import BaseModel, Field

# Never let the scheduler recreate/replace the agent's own container, even
# if a name collision check is somehow bypassed.
PROTECTED_NAMES = {"homelab-agent"}

ALLOWED_REGISTRIES = [
    r.strip().lower()
    for r in os.getenv("ALLOWED_REGISTRIES", "").split(",")
    if r.strip()
]
ALLOWED_HOST_PATHS = [
    os.path.normpath(os.path.expanduser(p.strip()))
    for p in os.getenv("ALLOWED_HOST_PATHS", "").split(",")
    if p.strip()
]
DEPLOY_PULL_TIMEOUT = int(os.getenv("DEPLOY_PULL_TIMEOUT", "600"))

_DOCKER_SOCKETS = {"/var/run/docker.sock", "/run/docker.sock"}


class PortSpec(BaseModel):
    container: int = Field(ge=1, le=65535)
    host: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"


class VolumeSpec(BaseModel):
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    read_only: bool = False


class ResourceSpec(BaseModel):
    cpus: float | None = Field(default=None, gt=0)
    memory_mb: int | None = Field(default=None, gt=0)


class CreateContainerRequest(BaseModel):
    image: str = Field(min_length=1)
    name: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    ports: list[PortSpec] = Field(default_factory=list)
    volumes: list[VolumeSpec] = Field(default_factory=list)
    restart_policy: Literal["no", "on-failure", "always", "unless-stopped"] = (
        "unless-stopped"
    )
    resources: ResourceSpec = Field(default_factory=ResourceSpec)
    labels: dict[str, str] = Field(default_factory=dict)
    pull: bool = True


class PolicyError(Exception):
    """A request that Docker was never asked to run. ``stage`` is one of
    ``policy`` / ``pull`` / ``create``."""

    def __init__(self, message: str, stage: str = "policy"):
        super().__init__(message)
        self.stage = stage


def _image_registry(image: str) -> str:
    """The registry host an image ref points at, ``docker.io`` if implicit."""
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first.lower()
    return "docker.io"


def normalize_image(image: str) -> str:
    """Add an explicit ``:latest`` so a pull doesn't fetch every tag."""
    last = image.rsplit("/", 1)[-1]
    if "@" in image or ":" in last:
        return image
    return f"{image}:latest"


def _host_path_allowed(source: str) -> bool:
    norm = os.path.normpath(os.path.expanduser(source))
    if norm in _DOCKER_SOCKETS:
        return False
    return any(
        norm == allowed or norm.startswith(allowed.rstrip("/") + "/")
        for allowed in ALLOWED_HOST_PATHS
    )


def _looks_like_host_path(source: str) -> bool:
    return source.startswith(("/", "./", "../", "~"))


def check_policy(req: CreateContainerRequest) -> None:
    if req.name in PROTECTED_NAMES:
        raise PolicyError(f"{req.name!r} is a protected container name")

    if ALLOWED_REGISTRIES:
        registry = _image_registry(req.image)
        if registry not in ALLOWED_REGISTRIES:
            raise PolicyError(
                f"image registry {registry!r} is not in ALLOWED_REGISTRIES "
                f"({', '.join(ALLOWED_REGISTRIES)})"
            )

    for volume in req.volumes:
        if _looks_like_host_path(volume.source):
            if not _host_path_allowed(volume.source):
                raise PolicyError(
                    f"host path {volume.source!r} is not under "
                    f"ALLOWED_HOST_PATHS — use a named volume instead"
                )


def _run_kwargs(req: CreateContainerRequest) -> dict:
    kwargs: dict = {
        "detach": True,
        "environment": dict(req.env),
        "labels": {**req.labels, "managed-by": "homelab-agent"},
        "ports": {
            f"{port.container}/{port.proto}": port.host for port in req.ports
        },
    }

    if req.name:
        kwargs["name"] = req.name

    volumes = {
        volume.source: {
            "bind": volume.target,
            "mode": "ro" if volume.read_only else "rw",
        }
        for volume in req.volumes
    }
    if volumes:
        kwargs["volumes"] = volumes

    if req.restart_policy != "no":
        kwargs["restart_policy"] = {"Name": req.restart_policy}

    if req.resources.cpus:
        kwargs["nano_cpus"] = int(req.resources.cpus * 1_000_000_000)
    if req.resources.memory_mb:
        kwargs["mem_limit"] = f"{req.resources.memory_mb}m"

    return kwargs


def deploy(client, req: CreateContainerRequest) -> dict:
    """Pull (optionally) and run a container. Raises ``PolicyError`` for a
    rejected request, a failed pull, or a Docker create error."""
    check_policy(req)

    image = normalize_image(req.image)

    if req.name:
        try:
            client.containers.get(req.name)
            raise PolicyError(
                f"a container named {req.name!r} already exists", stage="create"
            )
        except docker.errors.NotFound:
            pass

    if req.pull:
        try:
            client.images.pull(image)
        except docker.errors.APIError as error:
            raise PolicyError(
                f"pull failed: {getattr(error, 'explanation', None) or error}",
                stage="pull",
            )

    try:
        container = client.containers.run(image, **_run_kwargs(req))
    except docker.errors.APIError as error:
        raise PolicyError(
            f"create failed: {getattr(error, 'explanation', None) or error}",
            stage="create",
        )

    image_digest = None
    try:
        container.reload()
        digests = container.image.attrs.get("RepoDigests") or []
        image_digest = digests[0] if digests else None
    except Exception:  # noqa: BLE001 - digest is best-effort metadata
        pass

    return {
        "success": True,
        "id": container.short_id,
        "name": container.name,
        "image_digest": image_digest,
    }
