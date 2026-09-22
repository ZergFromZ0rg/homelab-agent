# Homelab Agent

A lightweight, portable Docker host agent for collecting live container metrics, detecting available GPUs, and providing basic Docker container controls through an HTTP API.

Homelab Agent is designed to run across multiple Linux Docker hosts and expose a consistent API to a central dashboard, monitoring system, or other application.

To stand up the agent alongside [homelab-dashboard](https://github.com/ZergFromZ0rg/homelab-dashboard) and Prometheus from scratch, follow that repo's [deployment guide](https://github.com/ZergFromZ0rg/homelab-dashboard/blob/main/docs/deployment.md).

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
- Create (pull an image and run a container from a spec — `POST /containers`)
- Delete (`DELETE /containers/{id}`)
- Compose stacks (`POST /stacks` runs `docker compose up` from YAML;
  `DELETE /stacks/{project}` tears it down)

The `homelab-agent` container is protected from destructive control operations through its own API.

`POST /containers` is meant for a scheduler (e.g. homelab-dashboard's Deploy
tab) to place a container on this host. It runs a policy check before Docker
is touched — protected names, an optional registry allowlist, and host
bind-mounts restricted to an allowlist (named volumes always allowed, the
Docker socket never). See [Creating containers](#creating-containers).

When `AGENT_TOKEN` is set, every mutating container route (create, start,
stop, restart, delete) requires it in an `X-Agent-Token` header.

### Stack Inventory

Homelab Agent reports a rebuild manifest of the host's Docker named volumes, images, networks, and per-container deployment shape (image, restart policy, ports, mounts) through `GET /inventory`. This lets a central job snapshot what each host needs to be recreated after a failure. See [Stack Inventory](#stack-inventory) below.

### Configuration Backup

On a schedule (default every 12 hours), Homelab Agent discovers the Compose projects on its host, copies their definition files with secrets redacted, writes `inventory.json`, and pushes `machines/<HOST_NAME>/` to a private GitHub repository. Each agent only writes its own host folder, so every machine in a fleet can back up to one repo. See [Configuration Backup](#configuration-backup-1) below.

### Network Connections

`GET /connections` reports who this host is actually talking to — remote
address, port, protocol and, when the kernel is counting, bytes in each
direction — by reading the conntrack table. Free with the backup feature's
host mount, one extra read-only mount without it; see
[Network Connections](#network-connections-1) below.

### Rebuild from the Dashboard

`POST /rebuild` pulls a Compose project's git checkout and brings it back
up with `--build`, so an agent (or anything else) can be updated from the
dashboard instead of over SSH. **Off unless `REBUILD_ENABLED=1`** — see
[Rebuilding](#rebuilding) below.

### Dashboard Registration

If `DASHBOARD_URL` is set, Homelab Agent registers itself with a
homelab-dashboard instance on startup and on a heartbeat, so a new machine
appears on the dashboard without editing any dashboard configuration. See
[Dashboard Registration](#dashboard-registration-1) below.

## GPU Autodetection

Homelab Agent reports every GPU it can see, from two sources at once:

- **`nvidia-smi`** — utilisation, VRAM, temperature, power and fan, one
  entry per card, so a multi-GPU or SLI host is covered by this alone. It
  is only present inside the container when the NVIDIA runtime is
  (`AGENT_RUNTIME=nvidia`, or `--gpus all`).
- **`/sys/class/drm`** — vendor, PCI id and temperature for AMD, Intel and
  NVIDIA cards alike. Docker mounts `/sys` into every container, so **AMD
  and Intel GPUs need no configuration at all.**

Both run, and NVIDIA cards that `nvidia-smi` already described are dropped
from the DRM results rather than listed twice. A host with an NVIDIA card
*and* an AMD one reports both — it used to report only the NVIDIA ones,
because the DRM scan was a fallback that never ran once `nvidia-smi`
answered.

**If an NVIDIA card is visible only to the DRM scan**, the container has
no NVIDIA runtime. That is a specific, fixable state, and it says so
rather than leaving you with a GPU block full of blanks:

```json
{
  "available": true, "count": 1,
  "hint": "NVIDIA card detected but this container has no NVIDIA runtime, so utilisation, VRAM, power and fan are unavailable. Set AGENT_RUNTIME=nvidia (compose) or --gpus all (docker run).",
  "devices": [{"vendor": "nvidia", "name": "NVIDIA GPU 10DE:2187", "runtime_missing": true, "temperature_c": 41.0, "utilization_percent": null}]
}
```

The dashboard shows that hint on the host card. Before it existed, the
only symptom was a card reporting no numbers, which looks exactly like an
idle one — a `--gpus` flag lost on a recreate went unnoticed for weeks.

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

### One command (from the dashboard)

The dashboard's Servers tab has an **Add a node** panel with this command,
its own address already filled in:

```bash
curl -fsSL https://raw.githubusercontent.com/ZergFromZ0rg/homelab-agent/main/install.sh | sh -s -- \
  --dashboard http://your-dashboard:8081 --rebuild
```

`install.sh` checks for Docker, clones this repo to `~/homelab-agent`,
writes a `.env`, detects an NVIDIA card *and* whether Docker actually has
the runtime registered, and starts the agent. It then registers itself and
appears on the dashboard within a minute.

Re-running it is safe: an existing checkout is updated rather than
replaced, and an existing `.env` keeps every value you don't pass. A
failed `git pull` on a re-run is reported and not fatal — a network blip
shouldn't leave a working node stopped.

| Flag | |
| --- | --- |
| `--dashboard URL` | register with this dashboard |
| `--token TOKEN` | the dashboard's `API_TOKEN`, if it has one |
| `--name NAME` | defaults to the hostname; **must match the Prometheus `job_name`** |
| `--agent-url URL` | how the dashboard reaches this agent (default `http://<name>:8123`) |
| `--rebuild` | allow the dashboard to pull and rebuild projects here |
| `--dir PATH` | where to put the checkout |

### With Compose (recommended)

`compose.yml` in this repo is a complete single-node deployment: the
Docker socket, the read-only host mount (which also gives
[Network Connections](#network-connections-1) its conntrack table for
free), a named volume for the backup working tree, and every environment
variable wired to a `.env`.

```bash
./setup.sh
docker compose up -d --build
```

`setup.sh` writes the `.env`: it detects the GPU, defaults `HOST_NAME` to
the machine's hostname, and asks about the dashboard and the tokens,
keeping any answers already in the file. Re-run it any time. Or copy
`.env.example` and fill it in by hand — it's the same four or five lines.

The same `compose.yml` works on every host; what differs goes in `.env`.

Prefer this over the `docker run` lines below if you expect to recreate
the container. A flag dropped from a long run command fails quietly — a
missing `--gpus all` turns full GPU telemetry into a bare
`NVIDIA GPU 10DE:xxxx` with no utilisation, VRAM or temperature, and
nothing tells you why. That is also why the runtime here is a variable
rather than a line to comment out.

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
      },
      "ports": {
        "3000/tcp": ["3000"]
      }
    }
  ]
}
```

### `ports`

Published host ports only (`docker run -p`), keyed by the container-side
port. A port that's `EXPOSE`d but not published to the host is omitted.
Empty (`{}`) if the container publishes nothing. A consumer can use the
first entry to link to whatever web UI the container serves, e.g.
`http://<HOST_NAME>:<port>`.

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
2. Copies each project's Compose file(s) plus sibling `*.yml` / `*.yaml`
   and shallow `*.json` from the host filesystem (mounted read-only into
   the container). `.env`, keys, databases, logs, `data/`,
   `node_modules/`, `.venv/`, `.github/`, build output, lockfiles, and
   `package.json` are skipped.
3. Redacts assignments whose name contains `PASSWORD`, `SECRET`, `TOKEN`,
   `API_KEY`, `PRIVATE_KEY`, `ACCESS_KEY` (or a bare `key:` / `pass:`),
   unless the value is a number, boolean, or `${VAR}` reference. URL
   credentials are redacted too; files matching a private-key or
   GitHub-token pattern are skipped entirely.
4. Writes `inventory.json` (the manifest from `GET /inventory`).
5. Clones/updates the repo, replaces `machines/<HOST_NAME>/` with the
   fresh copy, commits, and pushes. On a push race with another host it
   re-fetches and retries.

It does **not** back up the contents of volumes or bind mounts. Use
`inventory.json` as the checklist for restoring those from a separate
encrypted backup.

Redaction keys off variable names, so a secret stored under an
unrecognized name (for example a provider name like `openweathermap:` in a
homepage config) is **not** caught. Review the first commit from each host.

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

### Restore a host that failed or was wiped

The backup repo has everything needed to redeploy the stacks. It does
**not** contain volume data or real secret values — restore those
separately.

**1. Base system.** Install the OS and Docker (including the Compose
plugin). No need to match the old hostname, but note which `HOST_NAME` the
machine used — that is its folder in the repo.

**2. Get the backup.**

```bash
git clone https://github.com/your-user/homelab.git
cd homelab/machines/<host>
```

`inventory.json` in that folder lists every named volume, image (with
tag and digest), and network the host had — use it as the checklist for
the next two steps.

**3. Restore volume data** from your separate encrypted backup into the
Docker volumes named in `inventory.json`, *before* starting the stacks:

```bash
docker volume create <project>_<volume>
# then untar / rsync your data backup into that volume
```

Skip this for stateless stacks.

**4. Put secrets back.** Compose values in the backup are either
`REDACTED` or `${VAR}` references. For each stack, recreate its `.env`
file (or edit the compose file) with the real values. `.env` files are
never in the backup by design.

**5. Bring the stacks up.**

```bash
for stack in */; do (cd "$stack" && docker compose up -d); done
```

Compose pulls the images and recreates the networks. If a stack pinned
`latest`, check the running image against the digest in `inventory.json`.

**6. Redeploy the agent** on the restored host (see
[Run command (with backup)](#run-command-with-backup)) so it resumes
backing itself up, then:

```bash
curl -X POST http://localhost:8123/backup/run
```

Confirm `machines/<host>/` in the repo matches the restored machine.

## Creating containers

```http
POST /containers
```

Pulls the image (unless `"pull": false`) and runs a container. Body:

```json
{
  "image": "lscr.io/linuxserver/jellyfin:latest",
  "name": "jellyfin",
  "env": { "PUID": "1000", "TZ": "UTC" },
  "ports": [ { "container": 8096, "host": 8096, "proto": "tcp" } ],
  "volumes": [ { "source": "jellyfin-config", "target": "/config", "read_only": false } ],
  "restart_policy": "unless-stopped",
  "resources": { "cpus": 2.0, "memory_mb": 2048 },
  "labels": { "deployed-by": "homelab-dashboard" },
  "pull": true
}
```

Only `image` is required. `resources.cpus` maps to `--cpus`, `memory_mb` to
`--memory`. Success:

```json
{ "success": true, "id": "3f2a1b4c5d6e", "name": "jellyfin", "image_digest": "sha256:..." }
```

A rejected request returns `400` (or `502` for a Docker daemon error) with:

```json
{ "success": false, "error": "host path '/etc' is not under ALLOWED_HOST_PATHS ...", "stage": "policy" }
```

`stage` is `policy` (failed the pre-check), `pull`, or `create`.

| Env var | Default | |
| --- | --- | --- |
| `AGENT_TOKEN` | *(unset)* | Required in `X-Agent-Token` on every mutating route when set (constant-time compare). |
| `ALLOWED_REGISTRIES` | *(unset — any)* | Comma list, e.g. `lscr.io,docker.io,ghcr.io`. An image whose registry isn't listed is rejected. Not an *image* allowlist. |
| `ALLOWED_HOST_PATHS` | *(unset — none)* | Comma list of host path prefixes that may be bind-mounted (named volumes always pass; the socket and any dir containing it never do). Symlinks are resolved when visible. Only list dirs your workloads can't write to. |
| `ALLOWED_DEVICES` | *(unset — none)* | Comma list of host device path prefixes a container may be given, e.g. `/dev/dri` for GPU/QSV transcode. |
| `PROTECTED_CONTAINER_NAMES` | `homelab-agent` | Comma list the control/delete/deploy routes refuse to touch. Set this if the agent container isn't named `homelab-agent`. |
| `DEPLOY_PULL_TIMEOUT` | `600` | Seconds allowed for an image pull. |

```bash
curl -X POST http://localhost:8123/containers \
  -H 'content-type: application/json' \
  -H 'x-agent-token: <AGENT_TOKEN>' \
  -d '{"image":"traefik/whoami","name":"whoami","ports":[{"container":80,"host":18080}]}'
```

## Deleting containers

```http
DELETE /containers/{container_id}
```

Force-removes the container (protected names rejected with `403`). Returns
`{ "success": true, "container": "...", "action": "delete" }`.

## Compose stacks

```http
POST   /stacks              {name, compose_yaml, env}
GET    /stacks
DELETE /stacks/{project}?volumes=1
```

`POST /stacks` writes the compose file to `STACK_DIR/<name>/` and runs
`docker compose -p <name> up -d` (the image ships the Compose plugin and
talks to the host daemon over the mounted socket). `check_stack_policy`
walks every service first and rejects `build:`, `privileged`, `cap_add`,
`devices`, `network_mode: host`, `pid: host`, images outside
`ALLOWED_REGISTRIES`, and bind mounts outside `ALLOWED_HOST_PATHS` — named
volumes only. Success:

```json
{ "success": true, "project": "media", "services": [ { "name": "media-web-1", "id": "…", "status": "running" } ] }
```

`GET /stacks` lists the Compose projects that have containers on this host
(discovered from the `com.docker.compose.project` label, which is also
reported per-container in `/containers`). `DELETE /stacks/{project}` runs
`docker compose down` (`?volumes=1` adds `--volumes`).

| Env var | Default | |
| --- | --- | --- |
| `STACK_DIR` | `/data/stacks` | Where project files are written. Put it on a volume. |
| `STACK_COMPOSE_TIMEOUT` | `900` | Seconds for a compose up/down. |

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

## Network Connections

Per-host and per-container throughput answers *how much*. This answers
*who to*.

`GET /connections` parses the kernel's conntrack table
(`/proc/net/nf_conntrack`) and returns one row per conversation — grouped
by protocol, both addresses and destination port, so a client holding six
hundred connections open reads as one line rather than six hundred.

### Setup

If you already run the **configuration backup** feature, its `-v /:/host:ro`
mount means the host's conntrack table is *already* inside this container.
There is nothing to mount — the agent finds it at
`$HOST_ROOT/proc/1/net/nf_conntrack` on its own.

Otherwise add one read-only mount:

```bash
-v /proc/net/nf_conntrack:/host/nf_conntrack:ro
```

Either way, turn on byte accounting once on the host — without it the
kernel tracks flows but counts no bytes, and every row comes back with
`null` volumes:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
echo 'net.netfilter.nf_conntrack_acct=1' | sudo tee /etc/sysctl.d/99-conntrack-acct.conf
```

The response reports whether accounting is on, so the dashboard can tell
you to flip it rather than showing a table of zeros.

<details>
<summary>Why a mount is needed at all, and why not <code>network_mode: host</code></summary>

conntrack is per network namespace. The agent runs in its own, where the
table exists but is all but empty — so it has to read the host's.

The agent looks, in order, at: `CONNTRACK_FILE` if set, the narrow mount
at `/host/nf_conntrack`, `$HOST_ROOT/proc/1/net/nf_conntrack` (free with
the backup mount), and finally its own `/proc/net/nf_conntrack`. That last
one is only correct when the agent shares the host's networking, so if it
is the one found *and* it is empty, the route reports "not set up" rather
than "no traffic" — the two are indistinguishable otherwise.

It has to be PID 1's copy of the table: `/proc/net` is a symlink to
`/proc/self/net`, so reading a bind-mounted `/host/proc/net/nf_conntrack`
resolves back to *this* process's namespace and hands back the empty table
again.

Running the agent with `network_mode: host` would also work, and is not
recommended: it drops the `-p 8123:8123` mapping, which is how the
[Security](#security) section tells you to bind the agent to your tailnet
address. One read-only route isn't worth rewriting that.

</details>

### Response

```json
{
  "host": "bigboy",
  "updated_at": 1758470000.0,
  "available": true,
  "source": "/host/nf_conntrack",
  "accounting": true,
  "flows_total": 3412,
  "conversations_total": 214,
  "truncated": true,
  "attributed": true,
  "peers": [
    {
      "proto": "tcp",
      "family": "ipv4",
      "src": "192.168.1.40",
      "dst": "192.168.1.10",
      "dport": 8096,
      "flows": 4,
      "orig_bytes": 51200,
      "reply_bytes": 4294967296,
      "orig_packets": 620,
      "reply_packets": 3010000,
      "states": ["ESTABLISHED"],
      "container": "jellyfin",
      "container_id": "bbb222",
      "peer_container": null,
      "direction": "in",
      "peer": "192.168.1.40",
      "peer_port": 8096,
      "rx_bytes": 51200,
      "tx_bytes": 4294967296
    }
  ]
}
```

`src`/`dst` are the endpoints as conntrack records them: `src` opened the
connection, `orig_bytes` flowed `src` → `dst`, `reply_bytes` came back.
That's a fact about the flow, not about this host, so it is always
reported as-is.

**Container attribution** adds the host's own view on top. Docker rewrites
addresses in both directions, and the rewrite is the signal:

* **outbound** traffic is masqueraded, so the container's own address is
  still the original source;
* **inbound** traffic to a published port is DNAT'd, so the container's
  address appears as the *reply's* source — the original destination is
  the host. Matching a published host port catches this too, for setups
  where the reply tuple doesn't carry the container address.

When one end is recognised, the row gains `container`, `container_id`,
`direction` (`in`/`out`), `peer`, `peer_port`, and `rx_bytes`/`tx_bytes`
from **this host's** point of view. That last pair matters: conntrack
counts bytes per direction of the *connection*, so for an inbound flow the
reply counter is the host sending. Reading `orig`/`reply` as receive/send
would report a 4 GB upload as a 4 GB download.

`peer_container` is set when both ends are containers on a shared network,
so `jellyfin → postgres` reads as such.

Traffic that belongs to no container — something on the host itself — keeps
its raw endpoints with every attributed field `null`, and is instead
matched to the **process** that owns it (below). `"attributed": false` at
the top level means the container pass didn't run at all (the Docker
daemon was unreachable); the table is still returned.

### Process names, for what isn't a container

Rows no container claimed get `process` and `pid`, joined through the
socket inode: `/proc/net/{tcp,tcp6,udp,udp6}` gives the socket behind a
local port, and `/proc/<pid>/fd/*` says which process is holding it.

```json
{
  "proto": "tcp", "src": "192.168.1.10", "dst": "140.82.121.4",
  "dport": 443, "flows": 2, "orig_bytes": 9000, "reply_bytes": 120000,
  "container": null, "direction": null,
  "process": "sshd", "pid": 812
}
```

**No `pid: host` is needed** — the same host filesystem mount everything
else here uses is enough to *see* every host PID, and the socket tables
are read as PID 1's copy because `/proc/net` is a symlink to
`/proc/self/net` and would otherwise give this container's empty ones.

**`CAP_SYS_PTRACE` is needed**, though, and that one isn't obvious.
Reading another process's `/proc/<pid>/fd` is ptrace-level access, which
Docker drops by default — so without it every readlink is refused, no
socket resolves to a process, and the result is indistinguishable from a
host whose sockets genuinely have no owner. `compose.yml` adds it:

```yaml
    cap_add:
      - SYS_PTRACE
```

Comment it out if you'd rather not grant it. Container traffic is still
named without it; only host processes go unnamed, and the response then
says so rather than looking empty:

```json
{"processes": false, "processes_state": "denied",
 "processes_hint": "Traffic that isn't a container's can't be named: ..."}
```

`processes_state` says which of five things happened, and when it isn't
`ok` the response carries the evidence with it rather than leaving you to
go and collect it:

| state | |
| --- | --- |
| `ok` | names resolved |
| `off` | `CONNECTIONS_PROCESSES=0` |
| `no-sockets` | the socket tables weren't readable |
| `denied` | the walk was refused — add the capability above |
| `unmatched` | everything is readable and still nothing resolved |

`unmatched` is the honest one. It happens, it isn't a misconfiguration
you can fix from here, and `processes_facts` comes back with the counts
that would otherwise take several commands on the host to gather:

```json
{"processes_state": "unmatched",
 "processes_hint": "Host processes couldn't be matched to their sockets on this host — 260 processes visible, 82 with readable sockets, 52 sockets in the table. Container traffic is named regardless; this only affects the host's own.",
 "processes_facts": {"pids_visible": 260, "fds_readable": 82, "fds_refused": 0, "sockets": 52}}
```

Container traffic is named in every one of these states. This only ever
affects the host's own processes, which is the least interesting half.

The fd walk is the expensive part of this endpoint — it reads every
process's open file descriptors. It therefore runs **only when there are
unattributed rows to name**, so on a host where everything is
containerised nothing is read at all, and it stops as soon as every inode
it is looking for is accounted for.

Only established TCP sockets are considered. A listening socket has no
peer, so there is no flow for it to explain.

When the table isn't readable the route still answers `200`, with the fix:

```json
{
  "host": "bigboy",
  "available": false,
  "reason": "conntrack table not readable — mount the host's in (-v /proc/net/nf_conntrack:/host/nf_conntrack:ro) or set CONNTRACK_FILE"
}
```

### What it can't tell you

Which process inside a container owns a flow — the container is named, but
not the process within it, whose sockets live in its own namespace.
Per-container throughput totals are already on each container in
`GET /containers`.

A flow whose socket has already closed also can't be named: conntrack
keeps an entry for a while after the socket is gone, so a short-lived
connection can outlive its inode.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONNECTIONS_ENABLED` | `1` | `0` turns the route off entirely. |
| `CONNTRACK_FILE` | unset | Explicit path, tried before `/host/nf_conntrack`, `/host/proc/1/net/nf_conntrack`, `/proc/net/nf_conntrack`. |
| `CONNECTIONS_MAX_PEERS` | `50` | Rows returned. The rest are still counted in `conversations_total`. |
| `CONNECTIONS_CACHE` | `5` | Seconds a parse is reused. A busy host carries tens of thousands of flows. |
| `CONNECTIONS_PROCESSES` | `1` | `0` skips the process-name lookup and its walk of `/proc/<pid>/fd`. |
| `HOST_PROC` | unset | Explicit path to the host's `/proc`, tried before `$HOST_ROOT/proc`. |

### Running it

With `compose.yml` (which already has the host mount):

```bash
docker compose up -d --build
```

Or with `docker run`, if you aren't using the backup mount:

```bash
docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  -p 8123:8123 \
  -e HOST_NAME=bigboy \
  -e AGENT_TOKEN=your-shared-secret \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /proc/net/nf_conntrack:/host/nf_conntrack:ro \
  homelab-agent
```

Unlike `/containers` and `/inventory`, **this route is token-gated** — a
who-talks-to-whom table is a different class of data to hand out, so it
requires `X-Agent-Token` whenever `AGENT_TOKEN` is set.

```bash
curl -H "X-Agent-Token: your-shared-secret" http://bigboy:8123/connections
```

## Rebuilding

`POST /rebuild` runs, in the project's directory:

```bash
git pull --ff-only origin
docker compose up -d --build
```

`--ff-only` matters: a deployment checkout that has diverged from its
remote should stop and say so rather than merge or leave conflicts behind.

### This one is not policy-bounded, and is off by default

Every other mutating route works against an allowlist — which registries,
which host paths, which compose keys — because the agent talks to the host
daemon as root. This route deliberately punches through that: `git pull`
runs whatever hooks the repo carries and `--build` runs whatever the
Dockerfile says. It is arbitrary code execution on the host, by design.

So it is **off unless `REBUILD_ENABLED=1`**. A host that hasn't opted in
answers `403` and says so, and its containers report no rebuild target, so
the dashboard shows no button for them. Every attempt is written to the
`audit` logger either way.

### What can be rebuilt

Any container Compose started whose project directory is a git checkout.
Compose records the project, the service and the working directory on
every container it starts, so there's nothing to configure — the agent
reads the labels and checks for a `.git`. Containers started any other
way, or whose directory isn't a checkout, have nothing to pull and get no
target.

The working directory is read through the same host mount everything else
here uses (`HOST_ROOT`, `/host` by default).

### It always runs in a throwaway container

Every rebuild, not just the agent's own:

```bash
docker run -d -v /var/run/docker.sock:/var/run/docker.sock \
  -v <project>:<project> -w <project> \
  <this agent's image> \
  sh -c "git -c safe.directory=<project> pull --ff-only origin && docker compose up -d --build"
```

It uses this agent's own image, which already carries git, the Docker CLI
and the Compose plugin, so there is nothing extra to pull.

Running the ordinary ones in this process instead looks simpler and is
wrong. The agent sees the host filesystem under `HOST_ROOT`, so it would
run compose from `/host/srv/thing` while the daemon on the other end of
the socket knows that project as `/srv/thing`. Compose resolves a
service's relative bind mounts against the directory it ran in, so
`./data:/data` would reach the daemon as `/host/srv/thing/data` — a path
that doesn't exist on the host, which Docker would then create as an
empty directory. The containers come up with empty volumes and nothing
reports an error.

`safe.directory` isn't optional either: the checkout belongs to whoever
owns it on the host, this runs as root, and git has refused to touch a
repo owned by another user since 2.35.2.

### Remotes, and why ssh is fine

The helper has git and CA certificates. It does **not** have an `ssh`
binary or any of your keys — and shouldn't: this is an unauthenticated
read of a public repo, and handing a container a signing key to do it
would be absurd.

So an `ssh` remote is **not** something to fix on the host. ssh is the
right way for a person to push; it just isn't available in here. The same
repo is readable over https and the URL is derivable, so that's what gets
fetched:

```
git@github.com:you/thing.git      →  https://github.com/you/thing.git
ssh://git@gitlab.example.com/a/b  →  https://gitlab.example.com/a/b.git
```

Nothing on the host changes and your pushes keep using the keys they
always did. Every target reports both:

```json
{"remote": "git@github.com:zerg/homelab-dashboard.git",
 "fetch_url": "https://github.com/zerg/homelab-dashboard.git",
 "can_pull": true}
```

The pull names that URL rather than `origin`, precisely so the remote's
own transport isn't used.

`can_pull` is false only for a remote that is no kind of fetchable URL —
a local path, say — and `POST /rebuild` with `pull: true` against one of
those is a `400` rather than a helper that fails halfway.

A *private* repo will still fail, on credentials rather than transport;
that one can't be told apart from a public one without trying.

**Rebuilding the agent's own project** is the one case that can't report
back — `compose up` kills the process waiting for it. That job returns
`handed_off` rather than `done`, and the helper removes itself, since
nothing will be left to clean it up. The outcome shows up as the agent
coming back online.

### Jobs

A pull and build takes minutes, so `POST /rebuild` returns a job and the
caller polls it. One at a time per host — a second request while one is
running is a `409`.

```json
{
  "id": "9f2c1a4b8e70",
  "project": "homelab",
  "service": "homelab-agent",
  "working_dir": "/home/zerg/homelab/homelab-agent",
  "pull": true,
  "replaces_self": true,
  "state": "running",
  "steps": [
    {"command": "git pull --ff-only origin", "exit_code": 0, "output": "Already up to date.\n", "seconds": 0.4}
  ],
  "error": null
}
```

`state` is `running`, `done`, `failed`, or `handed_off`. Each step keeps
its last 8 KB of combined output, which is what you want when a build
fails.

| Route | |
| --- | --- |
| `POST /rebuild` | `{"container": "<id or name>", "pull": true}` → a job |
| `POST /rebuild/self` | rebuild *this agent* — it finds its own container, so the caller doesn't have to guess which one it is |
| `GET /rebuild` | `{"enabled": bool, "jobs": [...]}` |
| `GET /rebuild/{job_id}` | one job |

All three require `X-Agent-Token` when `AGENT_TOKEN` is set.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `REBUILD_ENABLED` | *(off)* | `1` turns the routes on. Nothing else here does anything until it is set. |
| `REBUILD_TIMEOUT` | `1800` | Seconds for the whole pull + build. |
| `REBUILD_HELPER_IMAGE` | *(this agent's image)* | Image for the self-rebuild helper. |

## Dashboard Registration

A homelab-dashboard instance normally has to be told about every agent it
should poll. Homelab Agent can skip that step: set `DASHBOARD_URL` and the
agent announces itself instead.

### What it does

On startup, and again every `REGISTER_INTERVAL` seconds, the agent sends:

```json
{ "name": "server-1", "url": "http://server-1:8123" }
```

to `POST {DASHBOARD_URL}/api/nodes`. The dashboard adds or refreshes that
entry and starts polling it on its next update cycle (a couple of
seconds) — nothing on the dashboard needs to change when a new machine
joins the fleet. If a heartbeat is missed for a while the dashboard marks
the node stale, and drops it after a longer period of silence (for
example, the agent's container was removed).

Registration is best-effort: if the dashboard is briefly unreachable, the
agent logs it and retries on the next interval.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DASHBOARD_URL` | *(unset)* | Base URL of the dashboard API, e.g. `http://dashboard:8081` (through its nginx `/api/` proxy) or `http://dashboard-api:8000` if reachable directly. Registration stays disabled until this is set. |
| `AGENT_URL` | `http://<HOST_NAME>:8123` | The address the dashboard should use to reach *this* agent. Override if the hostname the dashboard resolves differs from `HOST_NAME` (e.g. a different Tailscale MagicDNS name, or a LAN IP). |
| `REGISTER_TOKEN` | *(unset)* | Sent as `X-Register-Token` if the dashboard's own `REGISTER_TOKEN` is set. Must match. |
| `REGISTER_INTERVAL` | `60` | Seconds between heartbeats (minimum 15). |

`HOST_NAME` must be set to something other than the default `unknown` for
registration to run, and should match the `job` label the machine's
node_exporter is scraped under in Prometheus — that is how the dashboard
lines up an agent's containers with that machine's host metrics.

### Run command (with registration)

```bash
docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  -p 8123:8123 \
  -e HOST_NAME=server-1 \
  -e DASHBOARD_URL=http://dashboard:8081 \
  -e REGISTER_TOKEN=changeme \
  -v /var/run/docker.sock:/var/run/docker.sock \
  homelab-agent
```

That, plus pointing Prometheus at `server-1`'s node_exporter, is the whole
process for adding a machine — no dashboard redeploy or config edit.

## Project Structure

```text
homelab-agent/
├── main.py
├── connections.py
├── sockets.py
├── rebuild.py
├── setup.sh
├── install.sh
├── stack_backup.py
├── register.py
├── requirements.txt
├── compose.yml
├── .env.example
├── Dockerfile
├── .gitignore
├── LICENSE
└── README.md
```

## Security

The agent mounts `/var/run/docker.sock` and talks to the host daemon as
root. Anyone who can reach a mutating route (`POST /containers`, `POST
/stacks`, the control and delete routes) can create and control containers
on the host. Treat access to the API as equivalent to root on the host.

### Network boundary

Do **not** expose port 8123 to the public internet or an untrusted LAN.
Run the agent so its port is reachable only over a trusted overlay:

- Bind it to the Tailscale/WireGuard interface (`--host 100.x.y.z` on the
  uvicorn command, or a `ports:` mapping like `100.x.y.z:8123:8123`), not
  `0.0.0.0`.
- Set `AGENT_TOKEN` (matched on the dashboard side) so a stray request on
  the same overlay still can't deploy. The check is constant-time.

### Deploy/stack policy

`POST /containers` and `POST /stacks` accept specs from the dashboard
scheduler and run a policy check *before Docker is touched*
(`deploy.check_policy` / `stack_deploy.check_stack_policy`):

- **Single containers**: only image / env / ports / volumes / restart /
  resource-limits / labels are in the request model at all. Container name
  is charset-validated; `com.docker.*` and `org.opencontainers.*` labels
  are rejected.
- **Compose stacks** are checked against an *allowlist* of service keys —
  anything not on the list (`privileged`, `cap_add`, `security_opt` other
  than `no-new-privileges`, `userns_mode`, `devices` without an allowlist,
  `volumes_from`, `extra_hosts`, `group_add`, host/`container:`/`service:`
  namespaces for `network_mode`/`pid`/`ipc`/`uts`/`cgroup`, `build:`, …) is
  rejected. Top-level keys are allowlisted too, so `secrets:`/`configs:`
  with a `file:` host path don't slip through.
- **Volumes**: named volumes always pass. A bind mount (a source that
  starts `/`, `./`, `../` or `~`) must resolve — symlinks included, when
  the agent can see the path — under an `ALLOWED_HOST_PATHS` prefix, and
  never onto the docker socket or a directory that contains it (`/`,
  `/run`, `/var/run`, …). A named-volume *definition* that is really a bind
  (`driver_opts: {o: bind, device: /}`) is caught the same way.
- **Devices**: `/dev/*` passthrough is denied unless the host path is under
  an `ALLOWED_DEVICES` prefix (set `ALLOWED_DEVICES=/dev/dri` for GPU/QSV
  transcode).

The policy is a real boundary but not a sandbox. In particular: an
`ALLOWED_HOST_PATHS` prefix that a deployed container can write to lets
that container plant a symlink and escape the prefix on a *later* deploy —
so only allowlist directories your workloads don't get write access to.
The registry allowlist is a *registry* allowlist, not an image allowlist.
And the control/delete routes act on any container on the host, not only
scheduler-managed ones.

### Logging

The agent logs to stdout (`LOG_LEVEL`, default `INFO`). Every container /
stack mutation and every policy rejection goes to the `audit` logger:

```bash
docker logs homelab-agent 2>&1 | grep ' audit '
```

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

Deployed agents do **not** update themselves. New agent code is picked up
by rebuilding and recreating the container on each host. The configuration
backup keeps running on the old container until you do.

Pull the latest source:

```bash
git pull
```

Rebuild the image:

```bash
docker build -t homelab-agent .
```

Then recreate the running container using the same command you deployed it
with (keep `--gpus all` on NVIDIA hosts, and the backup env vars and
mounts if backup is enabled).

## Built With

- Python
- FastAPI
- Uvicorn
- Docker SDK for Python
- Linux DRM/sysfs
- NVIDIA System Management Interface (`nvidia-smi`) when available

## License

MIT. See [LICENSE](LICENSE).
