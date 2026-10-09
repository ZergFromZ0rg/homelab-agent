"""Live packet capture on this host: ``POST /capture`` starts one, ``GET
/capture`` returns what it has seen so far, ``DELETE /capture`` stops it, and
``GET /capture/pcap`` hands back the packet list as a file Wireshark opens.

The capture runs in a throwaway helper container on the **host's network**
with only the ``NET_RAW`` capability (see capture_worker.py for the sniffer
itself). This module starts it, reads its stdout, and keeps a small amount in
memory: the last few thousand packets, per-second totals, per-protocol counts
and the busiest conversations.

Limits, because sniffing is sensitive even on your own network:

- one capture at a time, ten minutes at most, then it stops by itself;
- the host's network, or one running container's: the helper joins that
  container's network namespace (``container:<id>``), which is what makes
  "what is qbittorrent actually talking to?" a one-click question;
- headers only unless payload is asked for: the first 64 bytes of it, or
  whole packets (what "Follow stream" needs). Names read out of a payload —
  a TLS server name, an HTTP Host and path (no query string), a DHCP host
  name — are kept regardless;
- promiscuous mode (see other devices' traffic on a mirror port) is a
  separate, explicit switch and is recorded with the capture;
- nothing is written to disk — stopping or restarting the agent discards it.
  That includes Docker's own logs: the helper runs with logging switched off
  and its output is read through an attach stream, because the default
  ``json-file`` driver would otherwise keep every packet (payload and all) in a
  root-owned file under /var/lib/docker until the container is removed;
- the filter is a host, a port, a protocol and/or an expression in the style of
  tcpdump (capture_filter.py), parsed here before anything starts.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import struct
import threading
import time

from docker.types import LogConfig

import capture_filter
import connections
import lan_scan
import rebuild
from log import audit, log

MAX_DURATION = 600
DEFAULT_DURATION = 60
MAX_PACKETS = 3000  # the ring the list and the pcap read from
PAYLOAD_MODES = ("none", "64", "full")
MAX_SERIES = 600  # one point a second
MAX_FLOWS = 200
MAX_NAMES = 2000  # addresses named by DNS answers seen during one capture
INTERFACES_TTL = 30  # seconds: listing them costs a helper container run
STDERR_LINES = 5  # kept from the helper, to say why it died
FILTER_PROTOS = ("tcp", "udp", "icmp", "arp", "dns", "tls", "http", "dhcp", "ntp", "icmpv6")
LABEL = "homelab-agent-capture"
HOST_NAME = os.getenv("HOST_NAME", "this host")
_IFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")  # a Linux interface name

_lock = threading.RLock()
_job: dict | None = None
_container = None
_starting = False  # a start is between its check and its job; see start()
_interfaces_cache: tuple[float, dict] | None = None


class CaptureError(Exception):
    pass


def validate_filter(raw: dict | None) -> dict:
    """A host, a port, a protocol and a filter expression get through — each
    checked, and all of them must match."""
    raw = raw or {}
    out: dict = {}
    expr = str(raw.get("expr") or "").strip()
    if expr:
        try:
            capture_filter.compile_filter(expr)
        except capture_filter.FilterError as error:
            raise CaptureError(f"filter: {error}") from error
        out["expr"] = expr
    host = str(raw.get("host") or "").strip()
    if host:
        try:
            out["host"] = str(ipaddress.ip_address(host))
        except ValueError as error:
            raise CaptureError(f"{host!r} isn't an IP address") from error
    port = raw.get("port")
    if port not in (None, ""):
        if isinstance(port, bool):
            raise CaptureError("the port must be a number")
        try:
            port = int(port)
        except (TypeError, ValueError) as error:
            raise CaptureError("the port must be a number") from error
        if not 1 <= port <= 65535:
            raise CaptureError("the port must be between 1 and 65535")
        out["port"] = port
    proto = str(raw.get("proto") or "").strip().lower()
    if proto:
        if proto not in FILTER_PROTOS:
            raise CaptureError(f"protocol must be one of {', '.join(FILTER_PROTOS)}")
        out["proto"] = proto
    return out


def interfaces(client) -> dict:
    """What can be captured on, and the one the host routes through. Cached
    briefly: it costs a helper container run, and the page asks on every open
    and again on every start."""
    global _interfaces_cache
    with _lock:
        if _interfaces_cache and time.monotonic() - _interfaces_cache[0] < INTERFACES_TTL:
            return _interfaces_cache[1]
    host = lan_scan.read_host(client)
    ifaces = [i for i in host.get("ifaces", []) if i.get("ip")]
    found = {
        "default": host.get("default"),
        "interfaces": [i["name"] for i in ifaces],
        # This host's own LAN addresses, so the viewer can call them by name.
        "addresses": [i["ip"] for i in ifaces if not i["name"].startswith(lan_scan.SKIP_IFACE)],
    }
    with _lock:
        _interfaces_cache = (time.monotonic(), found)
    return found


def context(client) -> dict:
    """Everything the page needs to set a capture up and read it: the host's
    interfaces, the running containers (a capture can join one's network) and
    the names of the addresses this host knows — its own, and each container's."""
    found = interfaces(client)
    containers, names = [], {}
    try:
        listed = connections.container_map(client)
    except Exception as error:  # noqa: BLE001 - the interfaces are still worth showing
        log.warning("capture: couldn't list containers: %s", error)
        listed = []
    for item in listed:
        containers.append({"name": item["name"], "ips": item["ips"]})
        for ip in item["ips"]:
            names[ip] = item["name"]
    for ip in found.get("addresses", []):
        names.setdefault(ip, HOST_NAME)
    containers.sort(key=lambda c: c["name"])
    return {**found, "host": HOST_NAME, "containers": containers, "names": names}


def _fresh(config: dict) -> dict:
    return {
        "state": "capturing",
        "iface": config["iface"],
        "filter": config["filter"],
        "payload": config["payload"],
        "promisc": config["promisc"],
        "container": config.get("container"),
        "duration": config["duration"],
        "started_at": time.time(),
        "finished_at": None,
        "error": None,
        "packets": [],  # newest last, capped at MAX_PACKETS
        "seq": 0,
        "series": [],  # {ts, pkts, bytes}
        "protocols": {},  # name -> {pkts, bytes}
        "flows": {},  # key -> {..., pkts, bytes, first, last}
        "totals": {"pkts": 0, "bytes": 0},
        "unlisted": 0,  # packets counted but not kept in the list
        "drops": 0,  # packets the kernel dropped because we read too slowly
        "issues": {},  # TCP problem -> count
        "names": {},  # address -> the name DNS answers in this capture gave it
    }


def _ingest(job: dict, line: str) -> bool:
    """Apply one line from the helper. False when it wasn't one of ours (a
    traceback, say), so the caller can keep it to explain a failure."""
    try:
        msg = json.loads(line)
        kind = msg.get("t")
    except (ValueError, AttributeError):
        return False
    if kind not in ("pkt", "tick", "end"):
        return False
    try:
        _apply(job, kind, msg)
    except (KeyError, TypeError, ValueError) as error:
        log.warning("capture: ignoring a malformed %s line: %s", kind, error)
    return True


def _apply(job: dict, kind: str, msg: dict) -> None:
    with _lock:
        if job is not _job:
            return
        if kind == "pkt":
            job["seq"] += 1
            msg["n"] = job["seq"]
            msg.pop("t", None)
            for name, address in msg.get("answers") or []:
                if address in job["names"] or len(job["names"]) < MAX_NAMES:
                    job["names"][address] = name
            job["packets"].append(msg)
            if len(job["packets"]) > MAX_PACKETS:
                del job["packets"][: len(job["packets"]) - MAX_PACKETS]
        elif kind == "tick":
            job["series"].append({"ts": msg["ts"], "pkts": msg["pkts"], "bytes": msg["bytes"]})
            del job["series"][: max(0, len(job["series"]) - MAX_SERIES)]
            job["totals"]["pkts"] += msg["pkts"]
            job["totals"]["bytes"] += msg["bytes"]
            job["unlisted"] += msg.get("skipped", 0)
            job["drops"] += msg.get("drops", 0)
            for issue, count in msg.get("issues", {}).items():
                job["issues"][issue] = job["issues"].get(issue, 0) + count
            for name, (pkts, size) in msg.get("protos", {}).items():
                row = job["protocols"].setdefault(name, {"pkts": 0, "bytes": 0})
                row["pkts"] += pkts
                row["bytes"] += size
            for proto, a, ap, b, bp, pkts, size, out, inn, *extra in msg.get("flows", []):
                key = f"{proto}|{a}|{ap}|{b}|{bp}"
                flow = job["flows"].get(key)
                if flow is None:
                    if len(job["flows"]) >= MAX_FLOWS * 5:
                        continue  # a scan or flood: keep what we have, stay bounded
                    flow = job["flows"][key] = {
                        "proto": proto, "a": a, "a_port": ap, "b": b, "b_port": bp,
                        "pkts": 0, "bytes": 0, "out": 0, "in": 0, "name": None, "issues": {}, "first": msg["ts"],
                    }
                flow["pkts"] += pkts
                flow["bytes"] += size
                flow["out"] += out
                flow["in"] += inn
                if extra and extra[0]:
                    flow["name"] = extra[0]
                if len(extra) > 1:
                    for issue, count in (extra[1] or {}).items():
                        flow["issues"][issue] = flow["issues"].get(issue, 0) + count
                flow["last"] = msg["ts"]
        elif kind == "end":
            reason = msg.get("reason", "")
            job["finished_at"] = msg.get("ts") or time.time()
            if reason in ("finished", "stopped"):
                job["state"] = "done" if reason == "finished" else "stopped"
            else:
                job["state"] = "error"
                job["error"] = reason


def _read(job: dict, container, stream) -> None:
    """Follow the helper's output until it exits, then clean it up."""
    tail: list[str] = []
    try:
        buffer = b""
        for chunk in stream:
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                text = line.decode("utf-8", "replace").strip()
                if text and not _ingest(job, text):
                    tail = [*tail, text[:300]][-STDERR_LINES:]
    except Exception as error:  # noqa: BLE001 - surfaced in the job
        log.warning("capture reader failed: %s", error)
        with _lock:
            if job is _job and job["state"] == "capturing":
                job["state"] = "error"
                job["error"] = f"lost the capture helper: {error}"
                job["finished_at"] = time.time()
    finally:
        with _lock:
            if job is _job and job["state"] == "capturing":
                # The helper vanished without saying why (killed, OOM, daemon
                # restart) — or crashed, in which case its last words are here.
                job["state"] = "error"
                job["error"] = "the capture helper stopped unexpectedly" + (f": {tail[-1]}" if tail else "")
                job["finished_at"] = time.time()
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001 - already gone is fine
            pass
        audit.info("packet capture on %s ended (%s)", job["iface"], job["state"])


def _clear_stale(client) -> None:
    for old in client.containers.list(all=True, filters={"label": LABEL}):
        try:
            old.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def start(client, body: dict | None) -> dict:
    global _job, _container, _starting
    body = body or {}
    # Check-and-reserve in one step: validating reads the host's interfaces
    # (a container run), so two near-simultaneous requests would otherwise both
    # pass the "already running" check and start two sniffers.
    with _lock:
        if _starting or (_job and _job["state"] == "capturing"):
            raise CaptureError("a capture is already running — stop it first")
        _starting = True
    try:
        config = _validated(client, body)
        container, stream = _launch(client, config)
        job = _fresh(config)
        with _lock:
            _job, _container = job, container
    finally:
        with _lock:
            _starting = False
    audit.info(
        "packet capture started on %s%s for %ss filter=%s payload=%s promisc=%s",
        f"{config['container']}'s network, " if config["container"] else "", config["iface"], config["duration"],
        config["filter"] or "none", config["payload"], config["promisc"],
    )
    threading.Thread(target=_read, args=(job, container, stream), daemon=True).start()
    return snapshot(0)


def _target_container(client, name: str):
    """The running container a capture should join, or CaptureError."""
    try:
        container = client.containers.get(name)
    except Exception as error:  # noqa: BLE001 - not found, or the daemon is unwell
        raise CaptureError(f"no container called {name!r} on this host") from error
    if container.status != "running":
        raise CaptureError(f"{container.name} isn't running, so it has no network to capture")
    return container


def _validated(client, body: dict) -> dict:
    container = str(body.get("container") or "").strip()
    target = _target_container(client, container) if container else None
    if target is not None:
        # Interfaces are those inside the container, which the host can't list;
        # "any" is safe there (one namespace: a packet crosses one interface).
        iface = str(body.get("iface") or "any").strip()
        if iface != "any" and not _IFACE.match(iface):
            raise CaptureError(f"{iface!r} isn't an interface name")
    else:
        available = interfaces(client)
        iface = str(body.get("iface") or available["default"] or "").strip()
        if iface != "any" and iface not in available["interfaces"]:
            raise CaptureError(f"{iface or 'no interface'!r} isn't a capturable interface on this host")
    try:
        duration = int(body.get("duration") or DEFAULT_DURATION)
    except (TypeError, ValueError) as error:
        raise CaptureError("the duration must be a number of seconds") from error
    if not 5 <= duration <= MAX_DURATION:
        raise CaptureError(f"the duration must be between 5 and {MAX_DURATION} seconds")

    payload = body.get("payload") or "none"
    if payload is True:  # older callers sent a boolean
        payload = "64"
    if payload not in PAYLOAD_MODES:
        raise CaptureError(f"payload must be one of {', '.join(PAYLOAD_MODES)}")
    promisc = body.get("promisc") is True  # not merely truthy: "false" is a string
    if promisc and iface == "any":
        raise CaptureError("promiscuous mode needs one interface, not all of them")
    return {
        "iface": iface,
        "duration": duration,
        "filter": validate_filter(body.get("filter")),
        "payload": payload,
        "promisc": promisc,
        "container": target.name if target is not None else None,
        "network_mode": f"container:{target.id}" if target is not None else "host",
    }


def _launch(client, config: dict):
    """Start the sniffer and return (container, output stream).

    Logging is switched off and the output read through an attach stream: the
    default json-file driver would write every packet record (payload hex
    included) to a root-owned file on the host for as long as the container
    exists. The stream is opened *before* the start so no early line is lost.
    """
    try:
        _clear_stale(client)
        container = client.containers.create(
            rebuild.helper_image(client),
            ["python", "/app/capture_worker.py"],
            network_mode=config["network_mode"],
            cap_drop=["ALL"],
            cap_add=["NET_RAW"],
            read_only=True,
            environment={"CAPTURE_CONFIG": json.dumps({k: v for k, v in config.items() if k != "network_mode"})},
            labels={LABEL: "1"},
            log_config=LogConfig(type=LogConfig.types.NONE),
        )
        try:
            stream = container.attach(stream=True, stdout=True, stderr=True)
            container.start()
        except Exception:
            container.remove(force=True)
            raise
        return container, stream
    except Exception as error:  # noqa: BLE001 - reported as-is
        raise CaptureError(f"couldn't start the capture helper: {error}") from error


def stop() -> dict:
    with _lock:
        job, container = _job, _container
    if job is None or job["state"] != "capturing":
        return snapshot(0)
    try:
        container.kill()
    except Exception as error:  # noqa: BLE001
        log.debug("capture kill: %s", error)
    with _lock:
        if job is _job and job["state"] == "capturing":
            job["state"] = "stopped"
            job["finished_at"] = time.time()
    return snapshot(0)


def snapshot(after: int = 0, limit: int = MAX_PACKETS) -> dict:
    """The job as it stands. ``after`` is the last packet number the caller
    has, so a poll only carries what is new; with 0 you get the latest ones.
    The limit defaults to the whole ring: a smaller one would silently drop
    packets between two polls once traffic passes ``limit`` per interval."""
    with _lock:
        if _job is None:
            return {"state": "idle"}
        job = _job
        packets = [p for p in job["packets"] if p["n"] > after]
        packets = packets[-limit:]
        flows = sorted(job["flows"].values(), key=lambda f: f["bytes"], reverse=True)[:MAX_FLOWS]
        return {
            "state": job["state"],
            "iface": job["iface"],
            "filter": job["filter"],
            "payload": job["payload"],
            "promisc": job["promisc"],
            "duration": job["duration"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "error": job["error"],
            "totals": dict(job["totals"]),
            "protocols": {k: dict(v) for k, v in job["protocols"].items()},
            "flows": [dict(f) for f in flows],
            "series": [dict(s) for s in job["series"]],
            "packets": [dict(p) for p in packets],
            "last": job["seq"],
            "unlisted": job["unlisted"],
            "drops": job["drops"],
            "issues": dict(job["issues"]),
            "container": job["container"],
            "names": dict(job["names"]),
        }


def pcap() -> bytes:
    """The packet list as a classic libpcap file: link type Ethernet, or raw
    IP when the capture is on a tunnel interface. Packets are as short as they
    were kept — headers only unless payload was on."""
    with _lock:
        packets = [dict(p) for p in (_job["packets"] if _job else [])]
    raw_ip = bool(packets) and all(p.get("l2", 0) == 0 for p in packets)
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101 if raw_ip else 1))
    for p in packets:
        data = bytes.fromhex(p.get("hex", ""))
        length = p["len"]
        if not raw_ip and p.get("l2", 0) == 0 and data:
            # A tunnel frame in a capture that is otherwise Ethernet ("any"):
            # give it a placeholder header so every record has the same shape.
            ethertype = b"\x86\xdd" if data[0] >> 4 == 6 else b"\x08\x00"
            data = bytes(12) + ethertype + data
            length += 14
        ts = p["ts"]
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000), len(data), length)
        out += data
    return bytes(out)
