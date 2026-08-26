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
