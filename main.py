import os
import docker

from fastapi import FastAPI, HTTPException

app = FastAPI()

client = docker.from_env()

HOST_NAME = os.getenv("HOST_NAME", "unknown")

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

@app.post("/containers/{container_id}/start")
def start_container(container_id: str):
    try:
        container = client.containers.get(container_id)
        container.start()

        return {
            "success": True,
            "container": container.name,
            "action": "start",
        }

    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404,
            detail="Container not found",
        )


@app.post("/containers/{container_id}/stop")
def stop_container(container_id: str):
    try:
        container = client.containers.get(container_id)
        container.stop()

        return {
            "success": True,
            "container": container.name,
            "action": "stop",
        }

    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404,
            detail="Container not found",
        )


@app.post("/containers/{container_id}/restart")
def restart_container(container_id: str):
    try:
        container = client.containers.get(container_id)
        container.restart()

        return {
            "success": True,
            "container": container.name,
            "action": "restart",
        }

    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404,
            detail="Container not found",
        )
