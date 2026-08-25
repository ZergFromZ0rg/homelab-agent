import os
import docker

from fastapi import FastAPI, HTTPException

app = FastAPI()

client = docker.from_env()

HOST_NAME = os.getenv("HOST_NAME", "unknown")
PROTECTED_CONTAINERS = {"homelab-agent"}

@app.get("/")
def root():
    return {
        "status": "homelab agent online",
        "host": HOST_NAME,
    }

@app.get("/containers")
def get_containers():
    containers = []

    for container in client.containers.list(all=True):
        containers.append({
            "id": container.short_id,
            "name": container.name,
            "image": (
                container.image.tags[0]
                if container.image.tags
                else container.image.short_id
            ),
            "status": container.status
        })

    return {
       "host": HOST_NAME,
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
