import os
import time
import threading
import subprocess
import secrets
import shutil
import glob
from pathlib import Path
import docker

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from log import log, audit
from stack_backup import StackBackup
from register import Registrar
import config
import connections
import deploy
import rebuild
import version
import volume_backup
from deploy import CreateContainerRequest, PolicyError
from stack_deploy import (
    CreateStackRequest,
    deploy_stack,
    list_stacks,
    remove_stack,
)

app = FastAPI()

client = docker.from_env()

HOST_NAME = os.getenv("HOST_NAME", "unknown")
# Containers the control routes refuse to touch (start/stop/restart/delete)
# and the deploy routes refuse to recreate. Configurable via
# PROTECTED_CONTAINER_NAMES; defaults to the agent's own name.
PROTECTED_CONTAINERS = deploy.PROTECTED_NAMES

# When set, the mutating container routes (create / start / stop / restart /
# delete, and the stack routes) require this value in an ``X-Agent-Token``
# header. Leave unset only when the agent's port is reachable *only* over a
# trusted overlay (Tailscale, WireGuard) — on a plain LAN, set it.
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "").strip()


def require_agent_token(x_agent_token: str | None = Header(default=None)) -> None:
    if AGENT_TOKEN and not secrets.compare_digest(x_agent_token or "", AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="invalid agent token")

registrar = Registrar(HOST_NAME)


container_cache = {
    "updated_at": None,
    "containers": [],
    "gpu": None,
}

cache_lock = threading.Lock()

# Set by the create/delete routes so the cache worker rebuilds its snapshot
# right away instead of on its next 2s tick — the dashboard then sees a
# just-deployed container without the extra lag.
cache_wake = threading.Event()


previous_io = {}


def add_io_rates(container_id, stats):
    now = time.time()

    network = stats.get("network", {})
    block_io = stats.get("block_io", {})

    current = {
        "time": now,
        "rx_bytes": network.get("rx_bytes", 0),
        "tx_bytes": network.get("tx_bytes", 0),
        "read_bytes": block_io.get("read_bytes", 0),
        "write_bytes": block_io.get("write_bytes", 0),
    }

    previous = previous_io.get(container_id)

    rx_bps = 0.0
    tx_bps = 0.0
    read_bps = 0.0
    write_bps = 0.0

    if previous:
        elapsed = now - previous["time"]

        if elapsed > 0:
            rx_bps = max(
                0.0,
                (current["rx_bytes"] - previous["rx_bytes"]) / elapsed,
            )

            tx_bps = max(
                0.0,
                (current["tx_bytes"] - previous["tx_bytes"]) / elapsed,
            )

            read_bps = max(
                0.0,
                (current["read_bytes"] - previous["read_bytes"]) / elapsed,
            )

            write_bps = max(
                0.0,
                (current["write_bytes"] - previous["write_bytes"]) / elapsed,
            )

    previous_io[container_id] = current

    network["rx_bps"] = round(rx_bps, 1)
    network["tx_bps"] = round(tx_bps, 1)

    block_io["read_bps"] = round(read_bps, 1)
    block_io["write_bps"] = round(write_bps, 1)

    return stats


def _safe_float(value):
    try:
        if value in (None, "", "N/A", "[Not Supported]"):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _read_text_file(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None


def get_nvidia_gpu_stats():
    nvidia_smi = shutil.which("nvidia-smi")

    if not nvidia_smi:
        return None

    try:
        result = subprocess.run(
            [
                nvidia_smi,
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit,fan.speed",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )

        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        if not lines:
            return None

        gpus = []

        for line in lines:
            parts = [part.strip() for part in line.split(",")]

            if len(parts) < 8:
                continue

            gpus.append({
                "vendor": "nvidia",
                "name": parts[0],
                "utilization_percent": _safe_float(parts[1]),
                "memory_used_mb": _safe_float(parts[2]),
                "memory_total_mb": _safe_float(parts[3]),
                "temperature_c": _safe_float(parts[4]),
                "power_draw_w": _safe_float(parts[5]),
                "power_limit_w": _safe_float(parts[6]),
                "fan_percent": _safe_float(parts[7]),
            })

        return gpus or None

    except Exception:
        return None


def get_drm_gpu_stats():
    gpus = []

    for card_path in sorted(glob.glob("/sys/class/drm/card*")):
        card = Path(card_path)

        # Only accept real DRM card directories:
        # card0, card1, card2, ...
        # Ignore connector entries such as card0-HDMI-A-1.
        suffix = card.name.removeprefix("card")

        if not suffix.isdigit():
            continue

        device_path = card / "device"

        if not device_path.exists():
            continue

        vendor_file = device_path / "vendor"

        if not vendor_file.exists():
            continue

        vendor_id = _read_text_file(device_path / "vendor")
        device_id = _read_text_file(device_path / "device")

        vendor_map = {
            "0x10de": "nvidia",
            "0x1002": "amd",
            "0x8086": "intel",
        }

        vendor = vendor_map.get(
            (vendor_id or "").lower(),
            "unknown",
        )

        name = f"{vendor.upper()} GPU"

        uevent = _read_text_file(device_path / "uevent")

        if uevent:
            for line in uevent.splitlines():
                if line.startswith("PCI_ID="):
                    name = f"{vendor.upper()} GPU {line.split('=', 1)[1]}"
                    break

        temperature_c = None

        for hwmon in glob.glob(
            str(device_path / "hwmon" / "hwmon*")
        ):
            temp_raw = _read_text_file(
                Path(hwmon) / "temp1_input"
            )

            if temp_raw:
                try:
                    temperature_c = round(
                        float(temp_raw) / 1000,
                        1,
                    )
                    break
                except ValueError:
                    pass

        gpus.append({
            "vendor": vendor,
            "name": name,
            "device_id": device_id,
            "utilization_percent": None,
            "memory_used_mb": None,
            "memory_total_mb": None,
            "temperature_c": temperature_c,
            "power_draw_w": None,
            "power_limit_w": None,
            "fan_percent": None,
        })

    return gpus or None


def get_gpu_stats():
    """Every GPU on this host, from whichever source can see it.

    ``nvidia-smi`` gives the full picture — utilisation, VRAM, temperature,
    power, fan — for every NVIDIA card, so a multi-GPU or SLI box is
    covered by it alone. It is only present when the container has the
    NVIDIA runtime.

    The DRM scan reads ``/sys/class/drm``, which Docker mounts into every
    container by default, so AMD and Intel cards need no configuration at
    all. It costs detail: vendor, PCI id and temperature, no utilisation.

    Both run. Previously the DRM scan was only a fallback, which meant a
    host with an NVIDIA card *and* an AMD one reported only the NVIDIA
    ones. Cards nvidia-smi already described are dropped from the DRM
    side so they aren't listed twice.
    """
    nvidia = get_nvidia_gpu_stats() or []
    drm = get_drm_gpu_stats() or []

    # nvidia-smi has already described every NVIDIA card in full detail.
    extra = [gpu for gpu in drm if gpu["vendor"] != "nvidia"] if nvidia else drm

    gpus = nvidia + extra

    if not gpus:
        return {"available": False, "count": 0, "devices": []}

    # An NVIDIA card that only the DRM scan can see means this container
    # has no NVIDIA runtime: the card is there, but everything worth
    # knowing about it isn't. That used to be indistinguishable from a
    # quiet GPU, so it went unnoticed for weeks at a time.
    runtime_missing = not nvidia and any(gpu["vendor"] == "nvidia" for gpu in drm)

    for gpu in gpus:
        if runtime_missing and gpu["vendor"] == "nvidia":
            gpu["runtime_missing"] = True

    stats = {"available": True, "count": len(gpus), "devices": gpus}

    if runtime_missing:
        stats["hint"] = (
            "NVIDIA card detected but this container has no NVIDIA runtime, "
            "so utilisation, VRAM, power and fan are unavailable. Set "
            "AGENT_RUNTIME=nvidia (compose) or --gpus all (docker run)."
        )

    return stats


def build_container_snapshot():
    containers = []

    for container in client.containers.list(all=True):
        try:
            container.reload()

            state = container.attrs.get("State", {})

            health = (
                state.get("Health", {}).get("Status")
                if state.get("Health")
                else None
            )

            containers.append({
                "id": container.short_id,
                "name": container.name,
                "image": (
                    container.image.tags[0]
                    if container.image.tags
                    else container.image.short_id
                ),
                "status": container.status,
                "health": health,
                "started_at": state.get("StartedAt"),
                "restart_count": container.attrs.get(
                    "RestartCount",
                    0,
                ),
                "protected": (
                    container.name
                    in PROTECTED_CONTAINERS
                ),
                "deployed_by": (container.labels or {}).get("deployed-by"),
                "compose_project": (container.labels or {}).get(
                    "com.docker.compose.project"
                ),
                "stats": add_io_rates(
                    container.id,
                    get_container_stats(container),
                ),
                "size": get_container_size(container),
                "ports": _container_ports(container),
                "rebuild": rebuild.summary_for(container.labels),
            })

        except Exception as error:
            log.debug("snapshot error for %s: %s", container.name, error)

    return containers


def cache_worker():
    while True:
        try:
            snapshot = build_container_snapshot()

            gpu = get_gpu_stats()

            with cache_lock:
                container_cache["containers"] = snapshot
                container_cache["gpu"] = gpu
                container_cache["updated_at"] = time.time()

        except Exception as error:
            log.warning("container cache update failed: %s", error)

        cache_wake.wait(timeout=2)
        cache_wake.clear()


def start_cache_worker():
    thread = threading.Thread(
        target=cache_worker,
        daemon=True,
    )

    thread.start()


def safe_divide(a, b):
    if not b:
        return 0
    return a / b


def calculate_cpu_percent(stats):
    cpu_stats = stats.get("cpu_stats", {})
    precpu_stats = stats.get("precpu_stats", {})

    cpu_total = (
        cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
    )

    system_total = (
        cpu_stats.get("system_cpu_usage", 0)
        - precpu_stats.get("system_cpu_usage", 0)
    )

    online_cpus = cpu_stats.get("online_cpus")

    if not online_cpus:
        percpu = cpu_stats.get("cpu_usage", {}).get("percpu_usage", [])
        online_cpus = len(percpu) or 1

    if cpu_total <= 0 or system_total <= 0:
        return 0.0

    return round(
        (cpu_total / system_total) * online_cpus * 100,
        2,
    )


def calculate_memory(stats):
    memory = stats.get("memory_stats", {})

    usage = memory.get("usage", 0)
    limit = memory.get("limit", 0)

    memory_stats = memory.get("stats", {})

    cache = (
        memory_stats.get("inactive_file")
        or memory_stats.get("total_inactive_file")
        or 0
    )

    actual_usage = max(usage - cache, 0)

    percent = (
        safe_divide(actual_usage, limit) * 100
        if limit
        else 0
    )

    return {
        "used_bytes": int(actual_usage),
        "limit_bytes": int(limit),
        "percent": round(percent, 2),
    }


def calculate_network(stats):
    networks = stats.get("networks", {}) or {}

    rx = 0
    tx = 0

    for interface in networks.values():
        rx += interface.get("rx_bytes", 0)
        tx += interface.get("tx_bytes", 0)

    return {
        "rx_bytes": int(rx),
        "tx_bytes": int(tx),
    }


def calculate_block_io(stats):
    entries = (
        stats.get("blkio_stats", {})
        .get("io_service_bytes_recursive", [])
        or []
    )

    read_bytes = 0
    write_bytes = 0

    for entry in entries:
        operation = entry.get("op", "").lower()
        value = entry.get("value", 0)

        if operation == "read":
            read_bytes += value
        elif operation == "write":
            write_bytes += value

    return {
        "read_bytes": int(read_bytes),
        "write_bytes": int(write_bytes),
    }


def get_container_size(container):
    image_size = 0

    try:
        image_size = int(
            container.image.attrs.get("Size", 0) or 0
        )
    except Exception as error:
        log.debug("image size lookup failed for %s: %s", container.name, error)

    try:
        url = client.api._url(
            "/containers/{0}/json",
            container.id,
        )

        response = client.api._get(
            url,
            params={"size": 1},
        )

        info = client.api._result(
            response,
            json=True,
        )

        return {
            "writable_bytes": int(info.get("SizeRw", 0) or 0),
            "rootfs_bytes": int(info.get("SizeRootFs", 0) or 0),
            "image_bytes": image_size,
        }

    except Exception as error:
        log.debug("container size lookup failed for %s: %s", container.name, error)

        return {
            "writable_bytes": 0,
            "rootfs_bytes": 0,
            "image_bytes": image_size,
        }


def get_container_stats(container):
    if container.status != "running":
        return {
            "cpu_percent": 0,
            "memory": {
                "used_bytes": 0,
                "limit_bytes": 0,
                "percent": 0,
            },
            "network": {
                "rx_bytes": 0,
                "tx_bytes": 0,
            },
            "block_io": {
                "read_bytes": 0,
                "write_bytes": 0,
            },
        }

    try:
        stats = container.stats(
            stream=False,
            one_shot=False,
        )

        return {
            "cpu_percent": calculate_cpu_percent(stats),
            "memory": calculate_memory(stats),
            "network": calculate_network(stats),
            "block_io": calculate_block_io(stats),
        }

    except Exception:
        return {
            "cpu_percent": 0,
            "memory": {
                "used_bytes": 0,
                "limit_bytes": 0,
                "percent": 0,
            },
            "network": {
                "rx_bytes": 0,
                "tx_bytes": 0,
            },
            "block_io": {
                "read_bytes": 0,
                "write_bytes": 0,
            },
        }




def _container_ports(container):
    host_config = container.attrs.get("HostConfig") or {}
    ports = {}

    for target, bindings in (host_config.get("PortBindings") or {}).items():
        host_ports = sorted({
            binding.get("HostPort")
            for binding in (bindings or [])
            if binding.get("HostPort")
        })

        if host_ports:
            ports[target] = host_ports

    return ports


def _compose_labels(labels):
    labels = labels or {}

    return {
        "project": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "working_dir": labels.get(
            "com.docker.compose.project.working_dir"
        ),
        "config_files": labels.get(
            "com.docker.compose.project.config_files"
        ),
    }


def get_volume_sizes():
    try:
        data = client.df()

    except Exception as error:
        log.debug("volume size lookup failed: %s", error)
        return {}

    sizes = {}

    for volume in data.get("Volumes") or []:
        name = volume.get("Name")
        usage = volume.get("UsageData") or {}
        size = usage.get("Size")

        if name is not None and isinstance(size, int) and size >= 0:
            sizes[name] = size

    return sizes


def get_volume_inventory(sizes_by_name):
    volumes = []

    for volume in client.volumes.list():
        attrs = volume.attrs or {}
        labels = attrs.get("Labels") or {}

        volumes.append({
            "name": volume.name,
            "driver": attrs.get("Driver"),
            "mountpoint": attrs.get("Mountpoint"),
            "created_at": attrs.get("CreatedAt"),
            "compose_project": labels.get(
                "com.docker.compose.project"
            ),
            "compose_volume": labels.get(
                "com.docker.compose.volume"
            ),
            "options": attrs.get("Options") or {},
            "size_bytes": sizes_by_name.get(volume.name),
        })

    volumes.sort(key=lambda item: item["name"] or "")
    return volumes


def get_image_inventory():
    images = []

    for image in client.images.list():
        attrs = image.attrs or {}

        images.append({
            "id": image.id,
            "tags": sorted(image.tags),
            "digests": sorted(attrs.get("RepoDigests") or []),
            "size_bytes": int(attrs.get("Size", 0) or 0),
            "created": attrs.get("Created"),
        })

    images.sort(
        key=lambda item: (
            item["tags"][0] if item["tags"] else item["id"]
        )
    )

    return images


def get_network_inventory():
    networks = []

    for network in client.networks.list():
        attrs = network.attrs or {}
        labels = attrs.get("Labels") or {}
        ipam_config = (attrs.get("IPAM") or {}).get("Config") or []

        networks.append({
            "name": network.name,
            "driver": attrs.get("Driver"),
            "scope": attrs.get("Scope"),
            "internal": attrs.get("Internal", False),
            "subnets": [
                entry.get("Subnet")
                for entry in ipam_config
                if entry.get("Subnet")
            ],
            "compose_project": labels.get(
                "com.docker.compose.project"
            ),
        })

    networks.sort(key=lambda item: item["name"] or "")
    return networks


def get_container_inventory():
    entries = []

    for container in client.containers.list(all=True):
        attrs = container.attrs or {}
        config = attrs.get("Config") or {}
        host_config = attrs.get("HostConfig") or {}
        labels = config.get("Labels") or {}

        restart_policy = (
            (host_config.get("RestartPolicy") or {}).get("Name") or ""
        )

        ports = _container_ports(container)

        mounts = []

        for mount in attrs.get("Mounts") or []:
            mounts.append({
                "type": mount.get("Type"),
                "source": mount.get("Name") or mount.get("Source"),
                "target": mount.get("Destination"),
                "rw": mount.get("RW", True),
            })

        try:
            image_ref = (
                container.image.tags[0]
                if container.image.tags
                else container.image.short_id
            )
            image_id = container.image.id

        except Exception:
            image_ref = config.get("Image")
            image_id = attrs.get("Image")

        entries.append({
            "name": container.name,
            "image": image_ref,
            "image_id": image_id,
            "restart_policy": restart_policy,
            "compose": _compose_labels(labels),
            "ports": ports,
            "mounts": mounts,
        })

    entries.sort(key=lambda item: item["name"] or "")
    return entries


@app.on_event("startup")
def startup_event():
    start_cache_worker()
    stack_backup.start()
    registrar.start()

def _own_working_dir() -> str | None:
    """This agent's own checkout, as seen from inside the container.

    Same labels the rebuild targets come from — if Compose started this
    agent from a git checkout, that's the source it was built from and the
    one a rebuild would pull.
    """
    own_id = os.getenv("HOSTNAME", "").strip()
    if not own_id:
        return None

    try:
        labels = (client.containers.get(own_id).labels or {})
    except Exception as error:  # noqa: BLE001
        log.debug("could not read this agent's own labels: %s", error)
        return None

    working_dir = labels.get("com.docker.compose.project.working_dir")
    if not working_dir:
        return None

    return str(rebuild.host_path(working_dir))


@app.get("/")
def root():
    return {
        "status": "homelab agent online",
        "host": HOST_NAME,
        "version": version.report(
            client, _own_working_dir(), os.getenv("HOSTNAME", "").strip()
        ),
    }


@app.get("/version")
def agent_version():
    """What this agent is running and whether it's current. Same block as
    ``GET /`` carries, on its own for pollers that only want this."""
    return {
        "host": HOST_NAME,
        **version.report(
            client, _own_working_dir(), os.getenv("HOSTNAME", "").strip()
        ),
    }


@app.get("/containers")
def get_containers():
    with cache_lock:
        containers = list(
            container_cache["containers"]
        )

        updated_at = container_cache[
            "updated_at"
        ]

        gpu = container_cache["gpu"]

    return {
        "host": HOST_NAME,
        "updated_at": updated_at,
        "gpu": gpu,
        "containers": containers,
    }


def build_inventory(sizes: bool = False):
    volume_sizes = get_volume_sizes() if sizes else {}

    return {
        "host": HOST_NAME,
        "generated_at": time.time(),
        "sizes_included": bool(sizes),
        "volumes": get_volume_inventory(volume_sizes),
        "images": get_image_inventory(),
        "networks": get_network_inventory(),
        "containers": get_container_inventory(),
    }


@app.get("/inventory")
def get_inventory(sizes: bool = False):
    return build_inventory(sizes)


stack_backup = StackBackup(
    docker_client=client,
    host_name=HOST_NAME,
    inventory_provider=lambda: build_inventory(sizes=True),
)


@app.post("/rebuild")
def start_rebuild(
    request: dict | None = None,
    x_agent_token: str | None = Header(default=None),
):
    """Pull and rebuild the Compose project a container belongs to.

    Off unless REBUILD_ENABLED is set: ``git pull`` runs repo hooks and
    ``--build`` runs the Dockerfile, so this is arbitrary code execution on
    the host by design and a host has to opt in to it.

    Returns a job to poll — a build takes minutes.
    """
    require_agent_token(x_agent_token)

    if not rebuild.enabled():
        raise HTTPException(
            status_code=403,
            detail="rebuilds are off on this host; set REBUILD_ENABLED=1 on its agent",
        )

    body = request or {}
    container_id = str(body.get("container") or "").strip()
    if not container_id:
        raise HTTPException(status_code=400, detail="container is required")

    # Not get_container_or_404: that refuses protected containers, and the
    # agent's own is protected. Rebuilding it is the point.
    container = find_container_or_404(container_id)
    target = rebuild.target_for(container.labels)

    if target is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{container.name} isn't a Compose project in a git checkout, "
                "so there's nothing to pull and rebuild"
            ),
        )

    try:
        return rebuild.start(client, target, pull=body.get("pull", True))
    except ValueError as error:
        # A pull that can't work on this remote. Naming the remote makes it
        # obvious why, which "cannot run ssh" never did.
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error))


@app.post("/rebuild/self")
def rebuild_self(x_agent_token: str | None = Header(default=None)):
    """Rebuild this agent's own Compose project.

    Exists so a caller doesn't have to work out which container the agent
    is. It knows — its own container id is its hostname — and guessing by
    name from the outside breaks the moment someone renames it.

    Always a self-rebuild, so the job comes back ``handed_off``: the work
    is passed to a throwaway container because this process is about to be
    replaced by it.
    """
    require_agent_token(x_agent_token)

    if not rebuild.enabled():
        raise HTTPException(
            status_code=403,
            detail="rebuilds are off on this host; set REBUILD_ENABLED=1 on its agent",
        )

    own_id = os.getenv("HOSTNAME", "").strip()
    if not own_id:
        raise HTTPException(
            status_code=400,
            detail="this agent can't identify its own container (no HOSTNAME)",
        )

    container = find_container_or_404(own_id)
    target = rebuild.target_for(container.labels)

    if target is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "this agent isn't running from a Compose project in a git "
                "checkout, so there's nothing to pull and rebuild"
            ),
        )

    try:
        return rebuild.start(client, target, pull=target["can_pull"])
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error))


@app.get("/rebuild")
def list_rebuilds(x_agent_token: str | None = Header(default=None)):
    require_agent_token(x_agent_token)
    return {"enabled": rebuild.enabled(), "jobs": rebuild.recent()}


@app.get("/rebuild/{job_id}")
def rebuild_status(job_id: str, x_agent_token: str | None = Header(default=None)):
    require_agent_token(x_agent_token)

    job = rebuild.status(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown rebuild job")
    return job


@app.get("/connections")
def get_connections(x_agent_token: str | None = Header(default=None)):
    """Who this host is talking to, from the kernel conntrack table.

    Token-gated even though it only reads — unlike /containers and
    /inventory, this says which remote hosts this box reaches and when,
    which is a different class of thing to hand out. Returns
    ``available: false`` with a reason when the table isn't mounted, so a
    host that hasn't opted in reports that rather than erroring.
    """
    require_agent_token(x_agent_token)
    return connections.snapshot(HOST_NAME, client)


@app.get("/backup")
def backup_status():
    return stack_backup.snapshot()


@app.post("/backup/run")
def backup_run():
    if not stack_backup.configured:
        raise HTTPException(
            status_code=400,
            detail=(
                "backup not configured; set BACKUP_REPO and GITHUB_TOKEN"
            ),
        )

    stack_backup.trigger()

    return {"success": True, "triggered": True}


@app.get("/config")
def get_config(x_agent_token: str | None = Header(default=None)):
    """Every setting this agent understands, and whether it can be changed.

    Readable even on a host that doesn't accept settings, so the dashboard
    can show what is configured and say what to do about the rest instead
    of an empty page.
    """
    require_agent_token(x_agent_token)
    return {"host": HOST_NAME, **config.snapshot()}


@app.put("/config")
def put_config(
    payload: dict,
    x_agent_token: str | None = Header(default=None),
):
    """Apply settings. Nothing here touches .env, compose or this container
    — the values go to a file this agent owns and are read back at call
    time, so the worst a bad request can do is misconfigure the agent."""
    require_agent_token(x_agent_token)

    try:
        return config.update(payload.get("settings") or payload)
    except config.ConfigError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/backup/store")
def backup_store(x_agent_token: str | None = Header(default=None)):
    """Just whether this host can receive backups, and where.

    Split out of ``/backup/volumes`` because that one measures every volume
    and every candidate directory — minutes of walking on a big host — and
    the question "can I send backups here" should cost nothing.
    """
    require_agent_token(x_agent_token)

    return {
        "host": HOST_NAME,
        "enabled": volume_backup.enabled(),
        "roots": volume_backup.roots(client),
        "receive_url": (
            config.get("BACKUP_PUBLIC_URL").strip()
            or config.get("AGENT_URL").strip()
            or None
        ),
        "encrypted": bool(volume_backup.passphrase()),
    }


@app.get("/backup/volumes")
def backup_volumes(x_agent_token: str | None = Header(default=None)):
    """What can be backed up here, and whether anything can be stored here.

    Both halves in one answer because the dashboard needs both to offer a
    job: volumes are what a source host can read, roots are what a
    destination host can write.
    """
    require_agent_token(x_agent_token)

    return {
        "host": HOST_NAME,
        "volumes": volume_backup.list_volumes(client),
        # Directories this host will back up: the roots it allows, and the
        # ones worth offering, sized so the form can show what a job costs
        # before anyone commits to it.
        "sources": {
            "dirs": volume_backup.source_dirs(),
            "candidates": volume_backup.candidate_dirs(client),
        },
        "store": {
            "enabled": volume_backup.enabled(),
            "roots": volume_backup.roots(client),
            "receive_url": (
                config.get("BACKUP_PUBLIC_URL").strip()
                or config.get("AGENT_URL").strip()
                or None
            ),
        },
    }


@app.get("/backup/projects")
def backup_projects(x_agent_token: str | None = Header(default=None)):
    """Every Compose project here and the data it owns, whether or not it is
    currently allowed to be backed up.

    This is the "what would I lose" question, so it has to include what
    nobody has configured yet — that is precisely the case worth knowing
    about.
    """
    require_agent_token(x_agent_token)

    return {
        "host": HOST_NAME,
        "projects": volume_backup.projects(client),
        "source_dirs": volume_backup.source_dirs(),
    }


@app.post("/backup/volumes/run")
def backup_volume_run(
    payload: dict,
    x_agent_token: str | None = Header(default=None),
):
    """Start a backup. Returns a job id, because a volume of any size takes
    far longer than a request should be held open for."""
    require_agent_token(x_agent_token)

    volume = str(payload.get("volume") or "").strip()
    path = str(payload.get("path") or "").strip()

    if not volume and not path:
        raise HTTPException(
            status_code=400, detail="a volume or a path is required"
        )

    remote = payload.get("remote") or None

    if remote is not None and not isinstance(remote, dict):
        raise HTTPException(status_code=400, detail="remote must be an object")

    try:
        return volume_backup.start(
            client,
            volume=volume or None,
            path=path or None,
            directory=str(payload.get("directory") or "").strip(),
            remote=remote,
            name=(str(payload.get("name")).strip() if payload.get("name") else None),
            stop_containers=bool(payload.get("stop_containers")),
        )

    except volume_backup.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error))

    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error))


@app.get("/backup/volumes/jobs")
def backup_volume_jobs(x_agent_token: str | None = Header(default=None)):
    require_agent_token(x_agent_token)
    return {"jobs": volume_backup.recent()}


@app.get("/backup/volumes/jobs/{job_id}")
def backup_volume_job(
    job_id: str,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)
    job = volume_backup.status(job_id)

    if job is None:
        raise HTTPException(status_code=404, detail="unknown backup job")

    return job


@app.post("/backup/receive")
async def backup_receive(
    request: Request,
    x_agent_token: str | None = Header(default=None),
    x_backup_dir: str | None = Header(default=None),
    x_backup_name: str | None = Header(default=None),
):
    """Take an archive another node's helper is streaming here.

    Async on purpose: the body arrives a chunk at a time and each write
    goes to a worker thread, so a multi-gigabyte volume never has to exist
    in this process's memory or block the loop that is still answering the
    dashboard.
    """
    require_agent_token(x_agent_token)

    from anyio import to_thread

    try:
        receiver = await to_thread.run_sync(
            volume_backup.Receiver, client, x_backup_dir or "", x_backup_name or ""
        )
    except volume_backup.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except OSError as error:
        raise HTTPException(status_code=500, detail=f"could not open the archive: {error}")

    try:
        async for chunk in request.stream():
            if chunk:
                await to_thread.run_sync(receiver.write, chunk)

        return await to_thread.run_sync(receiver.commit)

    except Exception as error:  # noqa: BLE001 - a partial archive must not survive
        await to_thread.run_sync(receiver.abort)
        log.warning("backup receive failed: %s", error)
        raise HTTPException(status_code=500, detail=f"upload failed: {error}")


@app.get("/backup/archives")
def backup_archives(
    directory: str,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)

    try:
        return {"directory": directory, "archives": volume_backup.list_archives(client, directory)}
    except volume_backup.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/backup/archives/verify")
def backup_archives_verify(
    payload: dict,
    x_agent_token: str | None = Header(default=None),
):
    """Read an archive back and report whether it is intact.

    Synchronous: it is bounded by the archive's size, and whoever pressed
    the button is waiting for the answer. FastAPI runs a sync route in a
    worker thread, so a slow one doesn't block the dashboard's polling.
    """
    require_agent_token(x_agent_token)

    try:
        return volume_backup.verify(
            client,
            str(payload.get("directory") or "").strip(),
            str(payload.get("name") or "").strip(),
        )
    except volume_backup.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/backup/archives/delete")
def backup_archives_delete(
    payload: dict,
    x_agent_token: str | None = Header(default=None),
):
    """Deleting is a POST, not a DELETE, because it takes a list of names
    in a body and a DELETE with a body is a fight with every proxy."""
    require_agent_token(x_agent_token)

    names = payload.get("names")

    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise HTTPException(status_code=400, detail="names must be a list of strings")

    try:
        return volume_backup.delete_archives(
            client, str(payload.get("directory") or "").strip(), names
        )
    except volume_backup.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error))


def find_container_or_404(container_id: str):
    """Look one up, protected or not."""
    try:
        return client.containers.get(container_id)

    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404,
            detail="Container not found",
        )


def get_container_or_404(container_id: str):
    """Look one up for the control routes, which must not touch a
    protected container.

    Protection means "don't stop, restart or delete this" — it is what
    keeps the agent from killing itself on request. It deliberately does
    *not* cover /rebuild, whose entire purpose for the agent's own
    container is to replace it with a newer build.
    """
    container = find_container_or_404(container_id)

    if container.name in PROTECTED_CONTAINERS:
        raise HTTPException(
            status_code=403,
            detail="This container is protected",
        )

    return container


@app.post("/containers")
def create_container(
    request: CreateContainerRequest,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)
    audit.info("create container: image=%s name=%s", request.image, request.name)

    try:
        result = deploy.deploy(client, request)
        cache_wake.set()
        audit.info("created %s (%s)", result.get("name"), result.get("id"))
        return result

    except PolicyError as error:
        audit.warning("rejected create %s: %s", request.image, error)
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": str(error),
                "stage": error.stage,
            },
        )

    except docker.errors.DockerException as error:
        audit.warning("create %s failed: %s", request.image, error)
        return JSONResponse(
            status_code=502,
            content={"success": False, "error": str(error), "stage": "create"},
        )


@app.post("/stacks")
def create_stack(
    request: CreateStackRequest,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)
    audit.info("deploy stack: %s", request.name)

    try:
        result = deploy_stack(client, request)
        cache_wake.set()
        audit.info(
            "stack %s up (%d services)", request.name, len(result.get("services", []))
        )
        return result

    except PolicyError as error:
        audit.warning("rejected stack %s: %s", request.name, error)
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": str(error),
                "stage": error.stage,
            },
        )


@app.get("/stacks")
def get_stacks():
    return {"host": HOST_NAME, "stacks": list_stacks(client)}


@app.delete("/stacks/{project}")
def delete_stack(
    project: str,
    volumes: bool = False,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)
    audit.info("remove stack: %s (volumes=%s)", project, volumes)

    try:
        result = remove_stack(client, project, volumes=volumes)
        cache_wake.set()
        return result

    except PolicyError as error:
        audit.warning("rejected stack removal %r: %s", project, error)
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": str(error), "stage": error.stage},
        )


@app.delete("/containers/{container_id}")
def delete_container(
    container_id: str,
    x_agent_token: str | None = Header(default=None),
):
    require_agent_token(x_agent_token)

    container = get_container_or_404(container_id)
    name = container.name

    try:
        container.remove(force=True)

    except docker.errors.APIError as error:
        audit.warning("delete %s failed: %s", name, error)
        return JSONResponse(
            status_code=502,
            content={"success": False, "error": str(error)},
        )

    cache_wake.set()
    audit.info("deleted container %s", name)
    return {"success": True, "container": name, "action": "delete"}


def _control(container_id: str, action: str) -> dict:
    container = get_container_or_404(container_id)
    getattr(container, action)()
    audit.info("%s container %s", action, container.name)
    return {"success": True, "container": container.name, "action": action}


@app.post("/containers/{container_id}/start")
def start_container(
    container_id: str, x_agent_token: str | None = Header(default=None)
):
    require_agent_token(x_agent_token)
    return _control(container_id, "start")


@app.post("/containers/{container_id}/stop")
def stop_container(
    container_id: str, x_agent_token: str | None = Header(default=None)
):
    require_agent_token(x_agent_token)
    return _control(container_id, "stop")


@app.post("/containers/{container_id}/restart")
def restart_container(
    container_id: str, x_agent_token: str | None = Header(default=None)
):
    require_agent_token(x_agent_token)
    return _control(container_id, "restart")
