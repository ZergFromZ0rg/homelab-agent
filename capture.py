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
- headers only unless payload is asked for, and then only 64 bytes of it
  (the one exception is a TLS ClientHello's server name, which is read and
  kept as a hostname — nothing else of the handshake is);
- nothing is written to disk — stopping or restarting the agent discards it;
- the filter is a host, a port and a protocol, validated here.
"""

from __future__ import annotations

import ipaddress
import json
import struct
import threading
import time

import lan_scan
import rebuild
from log import audit, log

MAX_DURATION = 600
DEFAULT_DURATION = 60
MAX_PACKETS = 3000  # the ring the list and the pcap read from
MAX_SERIES = 600  # one point a second
MAX_FLOWS = 200
FILTER_PROTOS = ("tcp", "udp", "icmp", "arp", "dns", "tls", "icmpv6")
LABEL = "homelab-agent-capture"

_lock = threading.RLock()
_job: dict | None = None
_container = None


class CaptureError(Exception):
    pass


def validate_filter(raw: dict | None) -> dict:
    """Only a host, a port and a protocol get through — each checked."""
    raw = raw or {}
    out: dict = {}
    host = str(raw.get("host") or "").strip()
    if host:
        try:
            out["host"] = str(ipaddress.ip_address(host))
        except ValueError as error:
            raise CaptureError(f"{host!r} isn't an IP address") from error
    port = raw.get("port")
    if port not in (None, ""):
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
    """What can be captured on, and the one the host routes through."""
    host = lan_scan.read_host(client)
    names = [i["name"] for i in host.get("ifaces", []) if i.get("ip")]
    return {"default": host.get("default"), "interfaces": names}


def _fresh(config: dict) -> dict:
    return {
        "state": "capturing",
        "iface": config["iface"],
        "filter": config["filter"],
        "payload": config["payload"],
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
    }


def _ingest(job: dict, line: str) -> None:
    try:
        msg = json.loads(line)
    except ValueError:
        return
    kind = msg.get("t")
    with _lock:
        if job is not _job:
            return
        if kind == "pkt":
            job["seq"] += 1
            msg["n"] = job["seq"]
            msg.pop("t", None)
            job["packets"].append(msg)
            if len(job["packets"]) > MAX_PACKETS:
                del job["packets"][: len(job["packets"]) - MAX_PACKETS]
        elif kind == "tick":
            job["series"].append({"ts": msg["ts"], "pkts": msg["pkts"], "bytes": msg["bytes"]})
            del job["series"][: max(0, len(job["series"]) - MAX_SERIES)]
            job["totals"]["pkts"] += msg["pkts"]
            job["totals"]["bytes"] += msg["bytes"]
            job["unlisted"] += msg.get("skipped", 0)
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
                        "pkts": 0, "bytes": 0, "out": 0, "in": 0, "name": None, "first": msg["ts"],
                    }
                flow["pkts"] += pkts
                flow["bytes"] += size
                flow["out"] += out
                flow["in"] += inn
                if extra and extra[0]:
                    flow["name"] = extra[0]
                flow["last"] = msg["ts"]
        elif kind == "end":
            reason = msg.get("reason", "")
            job["finished_at"] = msg.get("ts") or time.time()
            if reason in ("finished", "stopped"):
                job["state"] = "done" if reason == "finished" else "stopped"
            else:
                job["state"] = "error"
                job["error"] = reason


def _read(client, job: dict, container) -> None:
    """Follow the helper's stdout until it exits, then clean it up."""
    try:
        buffer = b""
        for chunk in container.logs(stream=True, follow=True, stdout=True, stderr=True):
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line.strip():
                    _ingest(job, line.decode("utf-8", "replace"))
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
                # The helper vanished without saying why (killed, OOM, daemon restart).
                job["state"] = "error"
                job["error"] = "the capture helper stopped unexpectedly"
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
    global _job, _container
    body = body or {}
    with _lock:
        if _job and _job["state"] == "capturing":
            raise CaptureError("a capture is already running — stop it first")

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

    config = {
        "iface": iface,
        "duration": duration,
        "filter": validate_filter(body.get("filter")),
        "payload": bool(body.get("payload")),
    }
    try:
        _clear_stale(client)
        container = client.containers.run(
            rebuild.helper_image(client),
            ["python", "/app/capture_worker.py"],
            detach=True,
            network_mode="host",
            cap_drop=["ALL"],
            cap_add=["NET_RAW"],
            read_only=True,
            environment={"CAPTURE_CONFIG": json.dumps(config)},
            labels={LABEL: "1"},
        )
    except Exception as error:  # noqa: BLE001 - reported as-is
        raise CaptureError(f"couldn't start the capture helper: {error}") from error

    job = _fresh(config)
    with _lock:
        _job, _container = job, container
    audit.info(
        "packet capture started on %s for %ss filter=%s payload=%s",
        iface, duration, config["filter"] or "none", config["payload"],
    )
    threading.Thread(target=_read, args=(client, job, container), daemon=True).start()
    return snapshot(0)


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


def snapshot(after: int = 0, limit: int = 400) -> dict:
    """The job as it stands. ``after`` is the last packet number the caller
    has, so a poll only carries what is new; with 0 you get the latest ones."""
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
