"""Docker networks on this host: what exists, who is attached, and the few
changes worth making from the dashboard.

Reading is one ``GET /networks``: every network with its driver, subnets,
gateway, flags, and the containers attached (with their address on it).

Writing is four operations — create a bridge network, remove one, connect a
container to one, disconnect it — gated by ``AGENT_TOKEN`` like every other
mutating route. The limits are about not cutting the dashboard off from the
host it is managing:

- Docker's own ``bridge`` / ``host`` / ``none`` can't be removed.
- A network with containers still on it can't be removed; disconnect them
  first, so a removal never silently strands a running service.
- Protected containers (the agent itself, by default) can't be connected or
  disconnected — detaching the agent from the network the dashboard reaches
  it on would take the host off the dashboard, with no way back from it.
- Only ``bridge`` networks are created. ``macvlan`` / ``ipvlan`` need a
  parent interface and change how the host's LAN sees it; that is a job for
  a person at the host, not a button.
"""

from __future__ import annotations

import ipaddress
import re

import docker

BUILTIN = {"bridge", "host", "none"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


class NetworkError(ValueError):
    """A request this module refuses; the message is shown to the user."""


def _summary(network) -> dict:
    attrs = network.attrs or {}
    ipam = (attrs.get("IPAM") or {}).get("Config") or []
    labels = attrs.get("Labels") or {}

    members = []
    for cid, info in (attrs.get("Containers") or {}).items():
        members.append(
            {
                "id": cid[:12],
                "name": info.get("Name"),
                "ipv4": (info.get("IPv4Address") or "").split("/")[0] or None,
                "ipv6": (info.get("IPv6Address") or "").split("/")[0] or None,
                "mac": info.get("MacAddress") or None,
            }
        )
    members.sort(key=lambda m: (m["name"] or ""))

    name = attrs.get("Name") or network.name

    return {
        "id": (attrs.get("Id") or network.id or "")[:12],
        "name": name,
        "driver": attrs.get("Driver"),
        "scope": attrs.get("Scope"),
        "internal": bool(attrs.get("Internal")),
        "attachable": bool(attrs.get("Attachable")),
        "ipv6": bool(attrs.get("EnableIPv6")),
        "subnets": [c["Subnet"] for c in ipam if c.get("Subnet")],
        "gateways": [c["Gateway"] for c in ipam if c.get("Gateway")],
        "created": attrs.get("Created"),
        "builtin": name in BUILTIN,
        "compose_project": labels.get("com.docker.compose.project"),
        "containers": members,
    }


def list_networks(client) -> list[dict]:
    # greedy=True inspects each network, which is what fills in "Containers".
    networks = client.networks.list(greedy=True)
    rows = [_summary(n) for n in networks]
    # Docker's own three last; the rest by name.
    rows.sort(key=lambda r: (r["builtin"], r["name"]))
    return rows


def _get(client, network_id: str):
    try:
        return client.networks.get(network_id)
    except docker.errors.NotFound as error:
        raise NetworkError(f"no network {network_id!r} on this host") from error


def create_network(
    client,
    name: str,
    *,
    subnet: str | None = None,
    internal: bool = False,
) -> dict:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise NetworkError(
            "network names are letters, digits, '.', '_' and '-', starting "
            "with a letter or digit"
        )
    if name in BUILTIN:
        raise NetworkError(f"{name!r} is one of Docker's own networks")

    ipam = None
    if subnet:
        try:
            parsed = ipaddress.ip_network(subnet.strip(), strict=True)
        except ValueError as error:
            raise NetworkError(f"not a subnet: {error}") from error
        ipam = docker.types.IPAMConfig(
            pool_configs=[docker.types.IPAMPool(subnet=str(parsed))]
        )

    try:
        network = client.networks.create(
            name,
            driver="bridge",
            internal=bool(internal),
            attachable=True,
            ipam=ipam,
            check_duplicate=True,
        )
    except docker.errors.APIError as error:
        raise NetworkError(error.explanation or str(error)) from error

    network.reload()
    return _summary(network)


def remove_network(client, network_id: str) -> str:
    network = _get(client, network_id)
    network.reload()
    summary = _summary(network)

    if summary["builtin"]:
        raise NetworkError(f"{summary['name']!r} is one of Docker's own networks")
    if summary["containers"]:
        names = ", ".join(m["name"] or m["id"] for m in summary["containers"])
        raise NetworkError(f"still in use by {names} — disconnect them first")

    try:
        network.remove()
    except docker.errors.APIError as error:
        raise NetworkError(error.explanation or str(error)) from error

    return summary["name"]


def _check_container(client, container: str, protected: set[str]):
    try:
        found = client.containers.get(container)
    except docker.errors.NotFound as error:
        raise NetworkError(f"no container {container!r} on this host") from error

    if found.name in protected:
        raise NetworkError(
            f"{found.name} is protected — changing its networks could take "
            "this host off the dashboard"
        )
    return found


def connect(client, network_id: str, container: str, protected: set[str]) -> dict:
    network = _get(client, network_id)
    target = _check_container(client, container, protected)

    if network.name in ("host", "none"):
        raise NetworkError(
            f"containers join {network.name!r} when they are created, not after"
        )

    try:
        network.connect(target)
    except docker.errors.APIError as error:
        raise NetworkError(error.explanation or str(error)) from error

    return {"network": network.name, "container": target.name}


def disconnect(
    client, network_id: str, container: str, protected: set[str]
) -> dict:
    network = _get(client, network_id)
    target = _check_container(client, container, protected)

    try:
        network.disconnect(target)
    except docker.errors.APIError as error:
        raise NetworkError(error.explanation or str(error)) from error

    return {"network": network.name, "container": target.name}
