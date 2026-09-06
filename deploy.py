"""Create and run a container from a spec sent by the dashboard scheduler.

The dashboard decides *where* a container goes; this module is the *how* on
the chosen host. ``check_policy`` rejects anything outside a configurable
allowlist before Docker is touched — that policy is the containment
boundary, because the agent talks to the host daemon as root.

Env knobs (all optional):
  ALLOWED_REGISTRIES   comma list, e.g. "lscr.io,docker.io,ghcr.io".
                       Empty = allow any registry (still not an *image*
                       allowlist — a bad image from an allowed registry
                       still runs).
  ALLOWED_HOST_PATHS   comma list of host path prefixes that may be
                       bind-mounted. Empty = named volumes only. A prefix
                       here must NOT be writable by a deployed container,
                       or a symlink planted inside it defeats the check.
  ALLOWED_DEVICES      comma list of host device paths a container may be
                       given (e.g. "/dev/dri" for GPU transcode). Empty =
                       no device passthrough.
  DEPLOY_PULL_TIMEOUT  seconds to allow for an image pull (default 600).
"""

from __future__ import annotations

import os
import re
from typing import Literal

import docker
from pydantic import BaseModel, Field

# Protects the agent's own container from being recreated/replaced. Also
# configurable — set PROTECTED_CONTAINER_NAMES if the agent container is
# not named "homelab-agent".
PROTECTED_NAMES = {
    n.strip()
    for n in os.getenv("PROTECTED_CONTAINER_NAMES", "homelab-agent").split(",")
    if n.strip()
}

# Docker's own rules for a container / compose-project name.
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")


def _env_list(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


ALLOWED_REGISTRIES = [r.lower() for r in _env_list("ALLOWED_REGISTRIES")]
ALLOWED_HOST_PATHS = [
    os.path.normpath(os.path.expanduser(p)) for p in _env_list("ALLOWED_HOST_PATHS")
]
ALLOWED_DEVICES = [
    os.path.normpath(p) for p in _env_list("ALLOWED_DEVICES")
]
DEPLOY_PULL_TIMEOUT = int(os.getenv("DEPLOY_PULL_TIMEOUT", "600"))

# The socket in any of its usual spots, plus the directories that hold it —
# mounting a *parent* of the socket hands over the daemon just the same.
_DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_SOCKET_DIRS = ("/", "/run", "/var", "/var/run", "/run/docker", "/var/run/docker")

# Caps so a malformed request can't blow up memory building SDK kwargs.
_MAX_LIST = 100


class PortSpec(BaseModel):
    container: int = Field(ge=1, le=65535)
    host: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"


class VolumeSpec(BaseModel):
    source: str = Field(min_length=1, max_length=1024)
    target: str = Field(min_length=1, max_length=1024)
    read_only: bool = False


class ResourceSpec(BaseModel):
    cpus: float | None = Field(default=None, gt=0, le=1024)
    memory_mb: int | None = Field(default=None, gt=0)


class CreateContainerRequest(BaseModel):
    image: str = Field(min_length=1, max_length=1024)
    name: str | None = Field(default=None, max_length=64)
    env: dict[str, str] = Field(default_factory=dict)
    ports: list[PortSpec] = Field(default_factory=list, max_length=_MAX_LIST)
    volumes: list[VolumeSpec] = Field(default_factory=list, max_length=_MAX_LIST)
    restart_policy: Literal["no", "on-failure", "always", "unless-stopped"] = (
        "unless-stopped"
    )
    resources: ResourceSpec = Field(default_factory=ResourceSpec)
    labels: dict[str, str] = Field(default_factory=dict)
    pull: bool = True


class PolicyError(ValueError):
    """A request that Docker was never asked to run. ``stage`` is one of
    ``policy`` / ``pull`` / ``create``. Subclasses ``ValueError`` so a
    pydantic field validator can raise it and get a clean 422."""

    def __init__(self, message: str, stage: str = "policy"):
        super().__init__(message)
        self.stage = stage


def valid_name(value: str) -> str:
    value = (value or "").strip()
    if not NAME_RE.match(value):
        raise PolicyError(
            f"{value!r} is not a valid name (letters, digits, '_', '.', '-')"
        )
    return value


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


def check_registry(image: str, *, where: str = "") -> None:
    if not ALLOWED_REGISTRIES:
        return
    registry = _image_registry(image)
    if registry not in ALLOWED_REGISTRIES:
        prefix = f"{where}: " if where else ""
        raise PolicyError(
            f"{prefix}image registry {registry!r} is not in ALLOWED_REGISTRIES "
            f"({', '.join(ALLOWED_REGISTRIES)})"
        )


def looks_like_host_path(source: str) -> bool:
    return source.startswith(("/", "./", "../", "~"))


def _is_socket_ish(norm: str) -> bool:
    """``norm`` is the docker socket, or a directory that would contain it."""
    if norm == "/" or norm in _SOCKET_DIRS or norm in _DOCKER_SOCKETS:
        return True
    return any(
        sock == norm or sock.startswith(norm.rstrip("/") + "/")
        for sock in _DOCKER_SOCKETS
    )


def host_path_allowed(source: str) -> bool:
    """True only if ``source`` resolves under an ALLOWED_HOST_PATHS prefix and
    is not the docker socket (or a directory that contains it)."""
    norm = os.path.normpath(os.path.expanduser(source))
    if _is_socket_ish(norm):
        return False

    # If the agent can see the path, resolve symlinks — a symlink inside an
    # allowed dir must not be a way out of it. Check the resolved target for
    # socket-ness too.
    try:
        if os.path.lexists(norm):
            resolved = os.path.realpath(norm)
            if _is_socket_ish(resolved):
                return False
            norm = resolved
    except OSError:
        pass

    return any(
        norm == allowed or norm.startswith(allowed.rstrip("/") + "/")
        for allowed in ALLOWED_HOST_PATHS
    )


def device_allowed(spec: str) -> bool:
    """``spec`` is a compose device string like ``/dev/dri:/dev/dri`` or
    ``/dev/dri/renderD128``. Only the host side matters."""
    host = os.path.normpath(str(spec).split(":", 1)[0])
    return any(
        host == allowed or host.startswith(allowed.rstrip("/") + "/")
        for allowed in ALLOWED_DEVICES
    )


def check_volumes(volumes, *, where: str = "") -> None:
    prefix = f"{where}: " if where else ""
    for volume in volumes:
        source = volume.source if hasattr(volume, "source") else str(volume)
        if looks_like_host_path(source) and not host_path_allowed(source):
            raise PolicyError(
                f"{prefix}bind mount {source!r} is not under ALLOWED_HOST_PATHS "
                f"— use a named volume"
            )


def check_policy(req: CreateContainerRequest) -> None:
    if req.name:
        valid_name(req.name)
        if req.name.strip() in PROTECTED_NAMES:
            raise PolicyError(f"{req.name!r} is a protected container name")

    check_registry(req.image)
    check_volumes(req.volumes)

    for key in req.labels:
        if key.startswith("com.docker.") or key.startswith("org.opencontainers."):
            raise PolicyError(f"label {key!r} is reserved and cannot be set")


def _safe_labels(labels: dict) -> dict:
    return {
        k: v
        for k, v in labels.items()
        if not k.startswith(("com.docker.", "org.opencontainers."))
    }


def _run_kwargs(req: CreateContainerRequest) -> dict:
    kwargs: dict = {
        "detach": True,
        "environment": dict(req.env),
        "labels": {**_safe_labels(req.labels), "managed-by": "homelab-agent"},
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
