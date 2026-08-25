# Homelab Agent

A lightweight Docker agent for exposing container information and basic container controls over an HTTP API.

Homelab Agent is designed to run on any Docker host and provide a simple interface that a central dashboard, monitoring system, or other application can use to view and control containers.

## Features

- List Docker containers on a host
- Report container name, image, ID, and status
- Start containers
- Stop containers
- Restart containers
- Identify hosts using a configurable `HOST_NAME`
- Lightweight FastAPI-based HTTP API
- Runs entirely inside Docker
- Suitable for multi-host homelab environments

## Requirements

- Docker
- Linux host with access to the Docker socket
- A trusted private network

The agent communicates with the host Docker daemon through:

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

Choose a name that identifies the Docker host and provide it using the `HOST_NAME` environment variable.

For example:

```bash
docker run -d \
  --name homelab-agent \
  --restart unless-stopped \
  -p 8123:8123 \
  -e HOST_NAME=server-1 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  homelab-agent
```

The agent will now listen on port `8123`.

```text
http://HOST_IP:8123
```

To verify that the agent is running:

```bash
curl http://HOST_IP:8123/
```

## API

### Agent Status

```http
GET /
```

Example response:

```json
{
  "status": "homelab agent online",
  "host": "server-1"
}
```

---

### List Containers

```http
GET /containers
```

Returns Docker containers visible to the host Docker daemon.

Example response:

```json
{
  "host": "server-1",
  "containers": [
    {
      "id": "a1b2c3d4e5f6",
      "name": "example-service",
      "image": "example/image:latest",
      "status": "running"
    }
  ]
}
```

---

### Start Container

```http
POST /containers/{container_id}/start
```

Example:

```bash
curl -X POST \
  http://HOST_IP:8123/containers/example-service/start
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "start"
}
```

---

### Stop Container

```http
POST /containers/{container_id}/stop
```

Example:

```bash
curl -X POST \
  http://HOST_IP:8123/containers/example-service/stop
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "stop"
}
```

---

### Restart Container

```http
POST /containers/{container_id}/restart
```

Example:

```bash
curl -X POST \
  http://HOST_IP:8123/containers/example-service/restart
```

Example response:

```json
{
  "success": true,
  "container": "example-service",
  "action": "restart"
}
```

Container names, IDs, or unique shortened IDs can be used where supported by Docker.

## Multi-Host Usage

The same agent can be deployed on multiple Docker hosts.

For example:

```text
                    Central Dashboard
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
         server-1       server-2       server-3
          :8123          :8123          :8123
             │             │             │
             ▼             ▼             ▼
           Docker          Docker          Docker
```

Each installation uses a different `HOST_NAME`.

For example:

```bash
-e HOST_NAME=server-1
```

and:

```bash
-e HOST_NAME=server-2
```

A central dashboard can query each agent and combine the results into a single interface.

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

Access to the Docker socket provides extremely powerful control over the host's Docker daemon.

Anyone who can access the Homelab Agent API can currently issue supported container control commands.

### Do not expose port 8123 directly to the public internet.

The agent should currently only be used on a trusted private network, such as:

- A private homelab LAN
- A private VPN
- A Tailscale network
- Another appropriately secured internal network

Firewall rules should be used to restrict access to trusted devices.

Authentication and more granular authorization are planned improvements.

## Updating

Pull the latest source:

```bash
git pull
```

Rebuild the image:

```bash
docker build -t homelab-agent .
```

Recreate the running container with the updated image.

## Built With

- Python
- FastAPI
- Docker SDK for Python
- Uvicorn

## License

No license has been specified yet.
