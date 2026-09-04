# Homelab Agent

A lightweight, portable Docker host agent for collecting live container metrics, detecting available GPUs, and providing basic Docker container controls through an HTTP API.

Homelab Agent is designed to run across multiple Linux Docker hosts and expose a consistent API to a central dashboard, monitoring system, or other application.

## Features

### Container Monitoring

Homelab Agent discovers containers through the host Docker daemon and reports:

- Container name
- Container ID
- Docker image
- Container status
- Docker health status
- Start time
- Restart count
- CPU utilization
- Memory usage
- Memory limit
- Memory utilization percentage
- Network receive totals
- Network transmit totals
- Live network receive rate
- Live network transmit rate
- Block I/O read totals
- Block I/O write totals
- Live block I/O read rate
- Live block I/O write rate
- Docker image size
- Writable layer size
- Root filesystem size

Container statistics are collected by a background worker and cached in memory so API requests do not need to synchronously query every container.

### Container Controls

The API supports:

- Start
- Stop
- Restart

The `homelab-agent` container is protected from destructive control operations through its own API.

### Stack Inventory

Homelab Agent reports a rebuild manifest of the host's Docker named volumes, images, networks, and per-container deployment shape (image, restart policy, ports, mounts) through `GET /inventory`. This lets a central job snapshot what each host needs to be recreated after a failure. See [Stack Inventory](#stack-inventory) below.

### Configuration Backup

On a schedule (default every 12 hours), Homelab Agent discovers the Compose projects on its host, copies their definition files with secrets redacted, writes `inventory.json`, and pushes `machines/<HOST_NAME>/` to a private GitHub repository. Each agent only writes its own host folder, so every machine in a fleet can back up to one repo. See [Configuration Backup](#configuration-backup-1) below.

## GPU Autodetection

Homelab Agent automatically searches for GPUs available to the container instead of assuming a specific GPU vendor.

The API exposes GPU information using a vendor-neutral structure:

```json
{
  "gpu": {
    "available": true,
    "count": 1,
    "devices": []
  }
}
```

This allows the same agent image to run on machines with different hardware.

### NVIDIA GPUs

When `nvidia-smi` is available inside the container, Homelab Agent collects detailed NVIDIA telemetry.

Available metrics include:

- GPU model
- GPU utilization
- VRAM used
- Total VRAM
- GPU temperature
- Power draw
- Power limit
- Fan speed

Example:

```json
{
  "available": true,
  "count": 1,
  "devices": [
    {
      "vendor": "nvidia",
      "name": "NVIDIA GPU",
      "utilization_percent": 0.0,
      "memory_used_mb": 1.0,
      "memory_total_mb": 4096.0,
      "temperature_c": 32.0,
      "power_draw_w": 7.4,
      "power_limit_w": 100.0,
      "fan_percent": 26.0
    }
  ]
}
```

### Intel / AMD / DRM GPUs

If NVIDIA telemetry is unavailable, Homelab Agent falls back to Linux DRM/sysfs GPU discovery.

This allows GPUs such as Intel integrated graphics and AMD GPUs to be detected without requiring `nvidia-smi`.

Depending on the hardware and driver, some telemetry may not be exposed through sysfs. Unsupported values are returned as `null`.

Example:

```json
{
  "available": true,
  "count": 1,
  "devices": [
    {
      "vendor": "intel",
      "name": "INTEL GPU 8086:0046",
      "device_id": "0x0046",
      "utilization_percent": null,
      "memory_used_mb": null,
      "memory_total_mb": null,
      "temperature_c": null,
      "power_draw_w": null,
      "power_limit_w": null,
      "fan_percent": null
    }
  ]
}
```

### Systems Without a Detected GPU

The agent does not require a GPU.

If no supported GPU is detected, the API returns:

```json
{
  "available": false,
  "count": 0,
  "devices": []
}
```

The rest of the agent continues operating normally.

## Requirements

- Linux
- Docker
- Access to the host Docker socket
- A trusted private network
- For configuration backup: a read-only host filesystem mount and a
  GitHub token (see [Configuration Backup](#configuration-backup-1))

Homelab Agent communicates with the host Docker daemon through:

```text
/var/run/docker.sock
```

## Installation

Clone the repository:

```bash
git clone https://github.com/ZergFromZ0rg/homelab-agent.git
cd homelab-agent
```

Build the Docker image:

```bash
docker build -t homelab-agent .
```

## Running the Agent

### Standard Docker Host

Choose a name identifying the Docker host using the `HOST_NAME` environment variable.

```bash
docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  -p 8123:8123 \
  -e HOST_NAME=server-1 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  homelab-agent
```

The API will listen on port `8123`.

Verify the agent locally:

```bash
curl http://localhost:8123/
```

Expected response:

```json
{
  "status": "homelab agent online",
  "host": "server-1"
}
```

## NVIDIA Hosts

Full NVIDIA telemetry requires the GPU to be exposed to the container.

The host must have a working NVIDIA driver and NVIDIA Container Toolkit configuration.

Run the agent with:

```bash
docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  --gpus all \
  -p 8123:8123 \
  -e HOST_NAME=gpu-server \
  -v /var/run/docker.sock:/var/run/docker.sock \
  homelab-agent
```

Verify that the GPU is visible inside the container:

```bash
docker exec homelab-agent nvidia-smi
```

If `nvidia-smi` works inside the container, Homelab Agent will automatically use it for NVIDIA telemetry.

Hosts without NVIDIA hardware do not need `--gpus all`.

## API

### Agent Status

```http
GET /
```

Returns basic agent status and host identity.

Example:

```json
{
  "status": "homelab agent online",
  "host": "server-1"
}
```

## Containers and Metrics

```http
GET /containers
```

Returns the latest cached container and GPU snapshot.

Example:

```json
{
  "host": "server-1",
  "updated_at": 1787764791.1110327,
  "gpu": {
    "available": false,
    "count": 0,
    "devices": []
  },
  "containers": [
    {
      "id": "a1b2c3d4e5f6",
      "name": "example-service",
      "image": "example/image:latest",
      "status": "running",
      "health": "healthy",
      "started_at": "2026-01-01T12:00:00Z",
      "restart_count": 0,
      "protected": false,
      "stats": {
        "cpu_percent": 0.5,
        "memory": {
          "used_bytes": 52428800,
          "limit_bytes": 8589934592,
          "percent": 0.61
        },
        "network": {
          "rx_bytes": 1048576,
          "tx_bytes": 2097152,
          "rx_bps": 1024.0,
          "tx_bps": 2048.0
        },
        "block_io": {
          "read_bytes": 4096,
          "write_bytes": 8192,
          "read_bps": 0.0,
          "write_bps": 0.0
        }
      },
      "size": {
        "writable_bytes": 1048576,
        "rootfs_bytes": 209715200,
        "image_bytes": 104857600
      }
    }
  ]
}
```

### `updated_at`

`updated_at` is a Unix timestamp representing when the latest background metrics snapshot completed.

Immediately after the agent starts, the cache may initially be empty while the first snapshot is collected.

Initial collection time depends on:

- Number of containers
- Docker daemon performance
- Host performance
- Metrics available for each container

## Stack Inventory

```http
GET /inventory
```

Returns a manifest of everything on the host that has to be recreated after
a rebuild: Docker **named volumes**, **images**, **networks**, and each
container's deployment shape (image, restart policy, published ports,
mounts). It contains no data bytes and no secrets (container environment is
not included), so it is safe to commit to a configuration repository.

Pass `?sizes=true` to include volume sizes. This calls the Docker
`system df` API and can take several seconds on a busy host, so it is off by
default.

Example:

```bash
curl "http://localhost:8123/inventory?sizes=true"
```

```json
{
  "host": "server-1",
  "generated_at": 1787764791.11,
  "sizes_included": true,
  "volumes": [
    {
      "name": "uptime-kuma_data",
      "driver": "local",
      "mountpoint": "/var/lib/docker/volumes/uptime-kuma_data/_data",
      "created_at": "2026-01-01T12:00:00Z",
      "compose_project": "uptime-kuma",
      "compose_volume": "data",
      "options": {},
      "size_bytes": 5242880
    }
  ],
  "images": [
    {
      "id": "sha256:...",
      "tags": ["louislam/uptime-kuma:1"],
      "digests": ["louislam/uptime-kuma@sha256:..."],
      "size_bytes": 419430400,
      "created": "2026-01-01T00:00:00Z"
    }
  ],
  "networks": [
    {
      "name": "uptime-kuma_default",
      "driver": "bridge",
      "scope": "local",
      "internal": false,
      "subnets": ["172.20.0.0/16"],
      "compose_project": "uptime-kuma"
    }
  ],
  "containers": [
    {
      "name": "uptime-kuma",
      "image": "louislam/uptime-kuma:1",
      "image_id": "sha256:...",
      "restart_policy": "unless-stopped",
      "compose": {
        "project": "uptime-kuma",
        "service": "uptime-kuma",
        "working_dir": "/home/user/docker/uptime-kuma",
        "config_files": "/home/user/docker/uptime-kuma/docker-compose.yml"
      },
      "ports": { "3001/tcp": ["3001"] },
      "mounts": [
        {
          "type": "volume",
          "source": "uptime-kuma_data",
          "target": "/app/data",
          "rw": true
        }
      ]
    }
  ]
}
```

The `generated_at` timestamp changes on every request; a consumer that
commits this file should strip it so an unchanged host produces no diff.

## Configuration Backup

Homelab Agent can keep a private Git repository up to date with every
Compose stack on its host, so a machine that dies can be rebuilt from the
repo.

### What it does, every cycle

1. Discovers Compose projects from the running containers' Docker labels
   (`com.docker.compose.project.*`), plus any directories listed in
   `STACK_DIRS`.
2. Reads each project's Compose file(s) and any sibling `*.yml` / `*.yaml`
   / `*.json` from the host filesystem (mounted read-only into the
   container).
3. Redacts assignments whose name contains `PASSWORD`, `SECRET`, `TOKEN`,
   `API_KEY`, `PRIVATE_KEY`, `ACCESS_KEY`, and credentials embedded in
   URLs. Files matching a private-key or GitHub-token pattern are skipped
   entirely. `.env` files, keys, databases, logs, and data directories are
   never copied.
4. Writes `inventory.json` (the manifest from `GET /inventory`).
5. Clones/updates the repo, replaces `machines/<HOST_NAME>/` with the
   fresh copy, commits, and pushes. On a push race with another host it
   re-fetches and retries.

It does **not** back up the contents of volumes or bind mounts. Use
`inventory.json` as the checklist for restoring those from a separate
encrypted backup.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BACKUP_REPO` | *(unset)* | `owner/repo` of the private backup repository. Backup stays idle until set. |
| `GITHUB_TOKEN` | *(unset)* | Fine-grained PAT with **Contents: read and write** on that repo only. |
| `BACKUP_INTERVAL_HOURS` | `12` | Hours between runs (minimum 5 minutes). |
| `BACKUP_BRANCH` | `main` | Branch to commit to. |
| `HOST_ROOT` | `/host` | Where the host filesystem is mounted in the container. |
| `STACK_DIRS` | *(unset)* | Extra host directories to scan for stopped projects, `:`-separated. |
| `BACKUP_ENABLED` | `true` | Set `false` to disable the worker entirely. |
| `BACKUP_RUN_ON_START` | `true` | Run once shortly after startup instead of waiting a full interval. |
| `BACKUP_WORKDIR` | `/data/repo` | Repo checkout path inside the container. Mount a volume to avoid re-cloning on restart. |
| `GIT_AUTHOR_NAME` | `homelab-agent` | Commit author name. |
| `GIT_AUTHOR_EMAIL` | `homelab-agent@users.noreply.github.com` | Commit author email. |

The token is passed to `git` per-command as an HTTP auth header; it is not
written into `.git/config` and is masked out of error messages.

### Create the token

1. GitHub → Settings → Developer settings → **Fine-grained personal access
   tokens** → Generate new token.
2. **Resource owner**: your account. **Repository access**: Only select
   repositories → the private backup repo.
3. **Permissions** → Repository permissions → **Contents: Read and write**.
   Nothing else is needed.
4. Copy the token and pass it as `GITHUB_TOKEN`. The same token works for
   every host.

### Run command (with backup)

```bash
docker volume create homelab-agent-repo

docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  -p 8123:8123 \
  -e HOST_NAME=server-1 \
  -e BACKUP_REPO=your-user/homelab \
  -e GITHUB_TOKEN=github_pat_xxx \
  -e BACKUP_INTERVAL_HOURS=12 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v homelab-agent-repo:/data \
  homelab-agent
```

`-v /:/host:ro` gives the agent read-only access to the Compose files
wherever they live on the host. Restrict it to `-v /opt/stacks:/host/opt/stacks:ro`
(and set `STACK_DIRS`) if you prefer a narrower mount.

### Check it

```bash
curl http://localhost:8123/backup
```

```json
{
  "enabled": true,
  "configured": true,
  "repo": "your-user/homelab",
  "branch": "main",
  "interval_hours": 12.0,
  "host_folder": "machines/server-1",
  "running": false,
  "last_run_at": 1787764791.1,
  "last_success_at": 1787764795.4,
  "last_result": "pushed a1b2c3d4e5",
  "last_error": null,
  "last_commit": "a1b2c3d4e5f6...",
  "projects": 7
}
```

Force a run immediately:

```bash
curl -X POST http://localhost:8123/backup/run
```

### Restore a host

```bash
git clone https://github.com/your-user/homelab.git
cd homelab/machines/<host>
for stack in */; do (cd "$stack" && docker compose up -d); done
```

Then restore volume data separately, using `inventory.json` as the list of
volumes and image tags to expect.

## Start Container

```http
POST /containers/{container_id}/start
```

Example:

```bash
curl -X POST \
  http://localhost:8123/containers/example-service/start
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "start"
}
```

## Stop Container

```http
POST /containers/{container_id}/stop
```

Example:

```bash
curl -X POST \
  http://localhost:8123/containers/example-service/stop
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "stop"
}
```

## Restart Container

```http
POST /containers/{container_id}/restart
```

Example:

```bash
curl -X POST \
  http://localhost:8123/containers/example-service/restart
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "restart"
}
```

Container names, full IDs, or unique shortened IDs may be used where supported by Docker.

## Protected Containers

Homelab Agent protects its own container from destructive API operations.

By default:

```text
homelab-agent
```

is considered protected.

The container still appears in monitoring results:

```json
{
  "name": "homelab-agent",
  "protected": true
}
```

Attempts to perform protected operations against it are rejected by the API.

This prevents a dashboard using Homelab Agent from accidentally shutting down the agent it depends on.

## Background Metrics Cache

Docker statistics can be relatively expensive to retrieve, particularly when a host is running many containers.

Homelab Agent therefore collects metrics using a background worker.

The general flow is:

```text
Docker Host
    |
    v
Homelab Agent
    |
    +--> Container discovery
    |
    +--> Container statistics
    |
    +--> Network / disk rates
    |
    +--> Container sizes
    |
    +--> GPU discovery
    |
    v
In-memory snapshot cache
    |
    v
GET /containers
```

API requests read the latest completed snapshot rather than triggering a complete metrics collection every time.

This keeps API requests responsive even when collecting Docker statistics takes several seconds.

## Multi-Host Usage

The same Homelab Agent image can be deployed across multiple Docker hosts.

```text
                    Central Dashboard
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
         server-1       server-2       server-3
          :8123          :8123          :8123
             |             |             |
             v             v             v
           Docker        Docker        Docker
```

Each installation can identify itself using:

```bash
-e HOST_NAME=server-1
```

A central dashboard can query each agent and combine the responses into one interface.

The hosts do not need identical hardware.

For example, the same agent can run on:

- An NVIDIA GPU server
- A machine with Intel integrated graphics
- An AMD GPU system
- A machine without a detectable GPU

Hardware-specific metrics are returned when available.

## Project Structure

```text
homelab-agent/
├── main.py
├── stack_backup.py
├── requirements.txt
├── Dockerfile
├── .gitignore
└── README.md
```

## Security

> **Warning:** Homelab Agent currently does not provide authentication.

The agent mounts:

```text
/var/run/docker.sock
```

Access to the Docker socket provides extremely powerful control over the host Docker daemon.

Anyone who can access the Homelab Agent API may be able to issue supported Docker control operations.

### Do not expose port 8123 directly to the public internet.

Homelab Agent should currently only be used on a trusted network such as:

- A private homelab LAN
- A private VPN
- A Tailscale network
- Another appropriately secured internal network

Firewall rules should restrict API access to trusted systems.

Authentication and more granular authorization are potential future improvements.

### Backup credential and host mount

When configuration backup is enabled the agent also holds:

- A `GITHUB_TOKEN` with write access to the backup repository. Use a
  fine-grained PAT scoped to that one repo with only **Contents: read and
  write**. It is kept in memory, passed to `git` as a per-command header,
  and masked from logs.
- A read-only mount of the host filesystem (`-v /:/host:ro`) so it can read
  Compose files. It is never mounted read-write. Narrow it to the
  directories that hold your stacks if you prefer.

Secret values in Compose files are redacted before anything is committed,
and files that look like private keys or tokens are skipped, but review the
first few commits to confirm nothing sensitive slips through for your
setup.

## Updating

Pull the latest source:

```bash
git pull
```

Rebuild the image:

```bash
docker build -t homelab-agent .
```

Then recreate the running container using the appropriate command for that host.

For NVIDIA hosts, remember to retain:

```text
--gpus all
```

when recreating the container.

## Built With

- Python
- FastAPI
- Uvicorn
- Docker SDK for Python
- Linux DRM/sysfs
- NVIDIA System Management Interface (`nvidia-smi`) when available

## License

No license has been specified yet.
