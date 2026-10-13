"""Where each container's web UI is, found by asking instead of guessing.

A link built from published ports alone breaks three ways:

* a container on the host network (Pi-hole) publishes nothing, so there is
  no link at all;
* a container publishes several ports and only one is a web UI
  (qBittorrent also publishes its torrent port);
* the app answers, but not the way a browser will ask: its root is a 403
  (Pi-hole wants ``/admin/``), or it refuses the name the browser uses
  (Homepage answers ``400 Host validation failed`` to ``thinkpad:3000``).

So the agent connects to each candidate port itself, sends the request the
browser will send (``Host: <node>:<port>``, the node name being what the
dashboard puts in the link), and reports the one that works:

    "web": {"port": 8053, "scheme": "http", "path": "/admin/",
            "status": 302, "ok": true, "host_rejected": false}

``"web": null`` means every candidate was reached and none speaks HTTP, or
there was nothing to try. The key is *absent* when the answer isn't known
yet (not probed, or a port that didn't connect), so the dashboard can fall
back to its own port heuristic rather than trust a guess in either direction.

Candidates: the host ports a container publishes, and for a host-network
container the TCP ports its own processes listen on (found through the
host's /proc, the same mount ``sockets.py`` uses). Ports bound to loopback
are skipped: a browser on another machine can't reach them.

Probing runs in a background thread and is cached, so ``/containers`` never
waits on it.

  WEB_LINKS  "0" turns it off. Default on.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
import urllib3

import sockets
from log import log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LISTEN = "0A"
CONNECT_TIMEOUT = 1.5
READ_TIMEOUT = 2.5

# How long an answer is trusted before asking again.
TTL_FOUND = 600.0
TTL_NONE = 300.0
TTL_UNKNOWN = 60.0

# When an app's root is a 403/404/405, where its UI might be instead. Each is
# only used if it actually answers, so a wrong entry costs a request, not a
# wrong link.
LANDING_PATHS = ("/admin/", "/web/", "/ui/", "/login", "/dashboard")

# Only a tie-breaker between ports that already answered as web UIs.
COMMON_WEB_PORTS = {80, 443, 3000, 3001, 5000, 8000, 8080, 8081, 8082, 8083, 8096, 8888, 9000, 9090, 9091}

MAX_PROCESSES = sockets.MAX_PROCESSES
_ANY = {"", "0.0.0.0", "::"}


def enabled() -> bool:
    return os.getenv("WEB_LINKS", "1").strip() not in ("0", "false", "no")


# --- finding candidate ports -------------------------------------------------


def gateway(route_text: str | None = None) -> str:
    """The host as seen from this container: the default route's next hop."""
    try:
        text = route_text if route_text is not None else Path("/proc/net/route").read_text()
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except (OSError, ValueError, IndexError):
        pass
    return "172.17.0.1"


def _loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def read_listeners(root: str | None = None) -> list[dict]:
    """TCP sockets in LISTEN state on the host: ``{ip, port, inode}``."""
    root = root or sockets.proc_root()
    rows, seen = [], set()

    for name in ("tcp", "tcp6"):
        try:
            text = Path(root, "1", "net", name).read_text()
        except OSError as error:
            log.debug("listen table %s unreadable: %s", name, error)
            continue

        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != LISTEN:
                continue
            ip, port = sockets.parse_address(fields[1])
            try:
                inode = int(fields[9])
            except ValueError:
                continue
            if port is None or ip is None or inode == 0 or (ip, port) in seen:
                continue
            seen.add((ip, port))
            rows.append({"ip": ip, "port": port, "inode": inode})

    return rows


def container_pids(container_id: str, root: str | None = None) -> set[int]:
    """Host PIDs that belong to a container, by cgroup path (works for
    cgroup v1 ``/docker/<id>`` and v2 ``docker-<id>.scope`` alike)."""
    root = root or sockets.proc_root()
    pids: set[int] = set()

    try:
        entries = sorted(Path(root).iterdir())
    except OSError:
        return pids

    for scanned, entry in enumerate(entries):
        if scanned > MAX_PROCESSES:
            break
        if not entry.name.isdigit():
            continue
        try:
            if container_id in (entry / "cgroup").read_text():
                pids.add(int(entry.name))
        except OSError:
            continue

    return pids


def host_network_listeners(container_id: str, root: str | None = None) -> list[dict]:
    """Listening, non-loopback TCP ports owned by a host-network container."""
    root = root or sockets.proc_root()
    listeners = [row for row in read_listeners(root) if not _loopback(row["ip"])]
    if not listeners:
        return []

    wanted = {row["inode"] for row in listeners}
    owned: set[int] = set()
    for pid in container_pids(container_id, root):
        inodes, _ = sockets._socket_inodes(Path(root, str(pid)))
        owned |= inodes & wanted

    return [row for row in listeners if row["inode"] in owned]


def listening_ports(attrs: dict, container_id: str, root: str | None = None) -> list[int] | None:
    """TCP ports a host-network container listens on, lowest first.

    ``None`` for any other container: what it exposes is what it publishes,
    which ``/containers`` already reports as ``ports``. A host-network
    container publishes nothing, so this is the only way to say what it
    holds on the host.
    """
    if (attrs.get("HostConfig") or {}).get("NetworkMode") != "host":
        return None
    return sorted({row["port"] for row in host_network_listeners(container_id, root)})


def candidates(attrs: dict, container_id: str, host: str, root: str | None = None) -> list[tuple[str, int]]:
    """``(address to connect to, port)`` for every port a browser could use."""
    host_config = attrs.get("HostConfig") or {}
    found: list[tuple[str, int]] = []

    if host_config.get("NetworkMode") == "host":
        for row in host_network_listeners(container_id, root):
            found.append((host if row["ip"] in _ANY else row["ip"], row["port"]))
    else:
        for target, bindings in (host_config.get("PortBindings") or {}).items():
            if not target.endswith("/tcp"):
                continue
            for binding in bindings or []:
                ip, port = binding.get("HostIp") or "", binding.get("HostPort")
                if not port or not str(port).isdigit() or (ip and _loopback(ip)):
                    continue
                found.append((host if ip in _ANY else ip, int(port)))

    return sorted(set(found), key=lambda c: c[1])


# --- asking a port -----------------------------------------------------------


def _host_header(node: str, scheme: str, port: int) -> str:
    return node if (scheme, port) in (("http", 80), ("https", 443)) else f"{node}:{port}"


def _get(scheme: str, address: str, port: int, path: str, host_header: str):
    """One GET. Returns ``(status, first bytes of body)``; raises on anything
    that isn't an HTTP answer."""
    shown = f"[{address}]" if ":" in address else address
    response = requests.get(
        f"{scheme}://{shown}:{port}{path}",
        headers={"Host": host_header, "User-Agent": "homelab-agent/link-check"},
        allow_redirects=False,
        timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
        verify=False,
        stream=True,
    )
    try:
        return response.status_code, response.raw.read(300, decode_content=True) or b""
    finally:
        response.close()


def _good(status: int) -> bool:
    # 401 is "alive, wants a login" — a perfectly good link.
    return status < 400 or status == 401


def _try(scheme: str, address: str, port: int, node: str):
    """The root answer for one scheme, or None if it isn't speaking it."""
    try:
        status, body = _get(scheme, address, port, "/", _host_header(node, scheme, port))
    except requests.RequestException:
        return None
    if scheme == "http" and status == 400 and b"HTTPS" in body.upper():
        return None  # plain HTTP sent to a TLS port
    return status


def probe(address: str, port: int, node: str) -> dict:
    """What is at ``address:port``.

    ``state`` is ``closed`` (nothing connected), ``silent`` (connected, not
    HTTP) or ``web``; a web answer also carries scheme, path, status, ``ok``
    (a browser landing here sees a page) and ``host_rejected`` (it answers
    by address but refuses the node's name).
    """
    try:
        socket.create_connection((address, port), timeout=CONNECT_TIMEOUT).close()
    except OSError:
        return {"state": "closed"}

    for scheme in ("http", "https"):
        status = _try(scheme, address, port, node)
        if status is None:
            continue

        result = {"state": "web", "scheme": scheme, "path": "/", "status": status,
                  "ok": _good(status), "host_rejected": False}

        if not result["ok"] and status in (400, 421):
            # Same request with the address as the name: if that works, the
            # app is refusing the node's name, not broken.
            try:
                plain, _ = _get(scheme, address, port, "/", f"{address}:{port}")
            except requests.RequestException:
                plain = None
            result["host_rejected"] = plain is not None and _good(plain)

        elif not result["ok"] and status in (403, 404, 405):
            for path in LANDING_PATHS:
                try:
                    landed, _ = _get(scheme, address, port, path, _host_header(node, scheme, port))
                except requests.RequestException:
                    continue
                if _good(landed):
                    result.update(path=path, status=landed, ok=True)
                    break

        return result

    return {"state": "silent"}


def _rank(result: dict, port: int) -> tuple:
    """Smaller is better."""
    quality = 0 if result["ok"] else 1 if result["host_rejected"] else 2
    status = result["status"]
    return (
        quality,
        0 if result["scheme"] == "http" else 1,
        0 if status < 300 else 1 if status < 400 else 2,
        0 if port in COMMON_WEB_PORTS else 1,
        port,
    )


def choose(probed: list[tuple[int, dict]]) -> tuple[bool, dict | None]:
    """``(known, web)`` from every candidate's probe."""
    webs = [(port, r) for port, r in probed if r["state"] == "web"]
    if webs:
        port, best = min(webs, key=lambda item: _rank(item[1], item[0]))
        return True, {"port": port, "scheme": best["scheme"], "path": best["path"],
                      "status": best["status"], "ok": best["ok"],
                      "host_rejected": best["host_rejected"]}
    # Everything connected and none was HTTP: confirmed no web UI. A port
    # that didn't connect at all (still starting, firewalled) proves nothing.
    if all(r["state"] == "silent" for _, r in probed):
        return True, None
    return False, None


# --- cache and worker --------------------------------------------------------

_lock = threading.Lock()
_cache: dict[str, dict] = {}  # full container id -> {sig, at, known, web, listening}


def lookup(container_id: str) -> tuple[bool, dict | None]:
    with _lock:
        entry = _cache.get(container_id)
    return (True, entry["web"]) if entry and entry["known"] else (False, None)


def lookup_listening(container_id: str) -> list[int] | None:
    """The cached ``listening_ports``; ``None`` when it isn't a host-network
    container or hasn't been looked at yet."""
    with _lock:
        entry = _cache.get(container_id)
    return entry["listening"] if entry else None


def _signature(container) -> str:
    attrs = container.attrs or {}
    host_config = attrs.get("HostConfig") or {}
    return json.dumps([
        (attrs.get("State") or {}).get("StartedAt"),
        host_config.get("NetworkMode"),
        host_config.get("PortBindings"),
    ], sort_keys=True)


def _ttl(entry: dict) -> float:
    return TTL_UNKNOWN if not entry["known"] else TTL_FOUND if entry["web"] else TTL_NONE


def inspect_container(container, node: str, host: str, root: str | None = None) -> tuple[bool, dict | None]:
    cands = candidates(container.attrs or {}, container.id, host, root)
    if not cands:
        return True, None
    return choose([(port, probe(address, port, node)) for address, port in cands])


def refresh(client, node: str, now: float | None = None) -> None:
    """Probe what is new or stale; forget containers that are gone."""
    now = time.time() if now is None else now
    host = gateway()
    running = []
    for container in client.containers.list():
        try:
            # list() returns a summary; the port bindings and start time
            # the signature is built from only come with a full inspect.
            container.reload()
        except Exception as error:  # noqa: BLE001
            log.debug("cannot inspect %s: %s", container.name, error)
            continue
        if container.status == "running":
            running.append(container)
    live = {c.id for c in running}

    with _lock:
        for gone in set(_cache) - live:
            del _cache[gone]
        due = [
            c for c in running
            if (e := _cache.get(c.id)) is None or e["sig"] != _signature(c) or now - e["at"] >= _ttl(e)
        ]

    def work(container):
        try:
            known, web = inspect_container(container, node, host)
            listening = listening_ports(container.attrs or {}, container.id)
        except Exception as error:  # noqa: BLE001
            log.debug("web link check for %s failed: %s", container.name, error)
            known, web, listening = False, None, None
        with _lock:
            _cache[container.id] = {
                "sig": _signature(container), "at": now,
                "known": known, "web": web, "listening": listening,
            }

    if due:
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(work, due))


def start(client, node: str, interval: float = 20.0) -> None:
    if not enabled():
        return

    def loop():
        while True:
            try:
                refresh(client, node)
            except Exception as error:  # noqa: BLE001
                log.warning("web link refresh failed: %s", error)
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="web-links").start()


def reset() -> None:
    with _lock:
        _cache.clear()
