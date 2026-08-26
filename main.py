import os
import time
import threading
import subprocess
import docker

from fastapi import FastAPI, HTTPException

app = FastAPI()

client = docker.from_env()

HOST_NAME = os.getenv("HOST_NAME", "unknown")
PROTECTED_CONTAINERS = {"homelab-agent"}


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


def get_gpu_stats():
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit,fan.speed",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )

        line = result.stdout.strip().splitlines()[0]
        parts = [part.strip() for part in line.split(",")]

        return {
            "name": parts[0],
            "utilization_percent": float(parts[1]),
            "memory_used_mb": float(parts[2]),
            "memory_total_mb": float(parts[3]),
            "temperature_c": float(parts[4]),
            "power_draw_w": float(parts[5]),
            "power_limit_w": float(parts[6]),
            "fan_percent": float(parts[7]),
        }

    except Exception as error:
        print(f"GPU lookup failed: {error}")
        return None


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




@app.on_event("startup")
def startup_event():
    start_cache_worker()

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
