import os
import time
import threading
import subprocess
import shutil
import glob
from pathlib import Path
import docker

from fastapi import FastAPI, HTTPException

from stack_backup import StackBackup
from register import Registrar

app = FastAPI()

client = docker.from_env()

HOST_NAME = os.getenv("HOST_NAME", "unknown")
PROTECTED_CONTAINERS = {"homelab-agent"}

registrar = Registrar(HOST_NAME)


container_cache = {
    "updated_at": None,
    "containers": [],
    "gpu": None,
}

cache_lock = threading.Lock()


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
    gpus = get_nvidia_gpu_stats()

    if not gpus:
        gpus = get_drm_gpu_stats()

    if not gpus:
        return {
            "available": False,
            "count": 0,
            "devices": [],
        }

    return {
        "available": True,
        "count": len(gpus),
        "devices": gpus,
    }


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
                "stats": add_io_rates(
                    container.id,
                    get_container_stats(container),
                ),
                "size": get_container_size(container),
                "ports": _container_ports(container),
            })

        except Exception as error:
            print(
                f"Snapshot error for "
                f"{container.name}: {error}"
            )

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
            print(
                f"Container cache update failed: "
                f"{error}"
            )

        time.sleep(2)


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
        print(
            f"Image size lookup failed for {container.name}: {error}"
        )

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
        print(
            f"Container size lookup failed for {container.name}: {error}"
        )

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
        print(f"Volume size lookup failed: {error}")
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

@app.get("/")
def root():
    return {
        "status": "homelab agent online",
        "host": HOST_NAME,
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


def get_container_or_404(container_id: str):
    try:
        container = client.containers.get(container_id)

    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404,
            detail="Container not found",
        )

    if container.name in PROTECTED_CONTAINERS:
        raise HTTPException(
            status_code=403,
            detail="This container is protected",
        )

    return container


@app.post("/containers/{container_id}/start")
def start_container(container_id: str):
    container = get_container_or_404(container_id)
    container.start()

    return {
        "success": True,
        "container": container.name,
        "action": "start",
    }


@app.post("/containers/{container_id}/stop")
def stop_container(container_id: str):
    container = get_container_or_404(container_id)
    container.stop()

    return {
        "success": True,
        "container": container.name,
        "action": "stop",
    }


@app.post("/containers/{container_id}/restart")
def restart_container(container_id: str):
    container = get_container_or_404(container_id)
    container.restart()

    return {
        "success": True,
        "container": container.name,
        "action": "restart",
    }
