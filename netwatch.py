"""Network watch: notice when something on the LAN claims an address it
shouldn't, or hands out leases it shouldn't.

Opt-in per host, off by default. When on, a helper container on the host's
network (netwatch_worker.py) passes this module the only two things it reads,
through a kernel filter: ARP claims ("192.168.1.10 is at aa:bb:...") and DHCP
server replies. It never sees, stores or forwards any other traffic.

What it raises (each with a severity the dashboard turns into an alert):

- **The gateway's address changed hands** (bad) — the signature of ARP
  spoofing, and also what replacing your router looks like. The message says so.
- **An address moved to another MAC while the old one was still active** (warn)
  — a duplicate address, a spoofer, or a laptop that went from Ethernet to
  Wi-Fi. If the old claim had been quiet for an hour it is just a lease handed
  to someone else, and is recorded as information.
- **A second DHCP server is answering** (warn) — two servers hand out
  conflicting leases, and a rogue one can point every client at its own DNS.
- **A new device appeared** (info) — a MAC never seen before. Informational:
  the LAN scan already covers "what is new"; this one says *when*.

State that has to survive a restart is kept in ``/data/netwatch.json``: whether
the watch is on, which MAC held which address, and which DHCP servers have been
seen — otherwise a spoof that happens while the agent is restarting, or on the
first claim after it, would look like the baseline.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from pathlib import Path

from docker.types import LogConfig

import lan_scan
import rebuild
from log import audit, log

STATE_FILE = Path(os.getenv("NETWATCH_FILE", "/data/netwatch.json"))
LABEL = "homelab-agent-netwatch"

LEARN_SECONDS = 300  # after the very first start: don't announce everyone as new
ACTIVE_SECONDS = 3600  # a finding stays "active" (an alert) this long after its last sighting
IDLE_BINDING_SECONDS = 3600  # an address quiet this long being reused is routine
MAX_FINDINGS = 200
MAX_INFO_FINDINGS = 60  # "new device" notes are cheap to produce and must not crowd out the rest
MAX_KNOWN = 2000
SAVE_EVERY = 30
RESTART_BACKOFF = (5, 15, 60)
STDERR_LINES = 5

# Virtual MACs that legitimately move between routers (VRRP, HSRP): a change
# of owner there is the protocol working, not an attack.
VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01", "00:00:5e:00:02", "00:00:0c:07:ac", "00:00:0c:9f:f")
SEVERITIES = ("info", "warn", "bad")

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _interesting_ip(value: str | None) -> bool:
    """A real, private unicast address worth tracking (not 0.0.0.0 probes,
    link-local, multicast or public)."""
    try:
        ip = ipaddress.ip_address(value or "")
    except ValueError:
        return False
    return ip.version == 4 and ip.is_private and not (ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_loopback)


def _interesting_mac(value: str | None) -> bool:
    return bool(value) and bool(_MAC.match(value)) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")


class Detector:
    """Turns ARP claims and DHCP replies into findings. No I/O: feed it events
    with the time they happened, read ``findings`` and ``export()``."""

    def __init__(self, saved: dict | None = None, *, now: float | None = None):
        saved = saved or {}
        self.bindings: dict[str, dict] = saved.get("bindings", {})  # ip -> {mac, first, last}
        self.known: dict[str, dict] = saved.get("known", {})  # mac -> {first, ip}
        self.servers: dict[str, dict] = saved.get("servers", {})  # server ip -> {mac, first, last}
        self.findings: dict[str, dict] = {}
        self.gateway: str | None = None
        started = now if now is not None else time.time()
        # Only the very first run has nothing to compare against.
        self.learning_until = started + LEARN_SECONDS if not self.known and not self.bindings else started
        self.dirty = False

    # --- helpers ---------------------------------------------------------------

    def _raise(self, key: str, kind: str, severity: str, title: str, message: str, now: float, **extra) -> dict:
        """A new finding, or another sighting of one already raised."""
        finding_id = hashlib.sha1(key.encode()).hexdigest()[:10]
        found = self.findings.get(finding_id)
        if found:
            found["last"] = now
            found["count"] += 1
            return found
        found = {
            "id": finding_id, "kind": kind, "severity": severity, "title": title, "message": message,
            "at": now, "last": now, "count": 1, **extra,
        }
        self.findings[finding_id] = found
        self._evict()
        return found

    def _evict(self) -> None:
        """Keep the list bounded without ever losing what matters. A flood of
        new MAC addresses (a phone that randomises its address, or someone
        doing it on purpose) produces a stream of information notes; they go
        first, oldest first, so an alert can't be pushed out by noise."""
        info = sorted((f for f in self.findings.values() if f["severity"] == "info"), key=lambda f: f["last"])
        for stale in info[: max(0, len(info) - MAX_INFO_FINDINGS)]:
            del self.findings[stale["id"]]
        while len(self.findings) > MAX_FINDINGS:
            rank = {"info": 0, "warn": 1, "bad": 2}
            worst_last = min(self.findings.values(), key=lambda f: (rank.get(f["severity"], 0), f["last"]))
            del self.findings[worst_last["id"]]

    def _trim(self) -> None:
        for table in (self.known, self.bindings):
            if len(table) > MAX_KNOWN:
                for stale in sorted(table, key=lambda k: table[k].get("last", table[k].get("first", 0)))[: len(table) - MAX_KNOWN]:
                    del table[stale]

    # --- ARP -------------------------------------------------------------------

    def observe_arp(self, ip: str, mac: str, now: float) -> None:
        if not (_interesting_ip(ip) and _interesting_mac(mac)):
            return
        if mac.startswith(VIRTUAL_MAC_PREFIXES):
            return

        if mac not in self.known:
            self.known[mac] = {"first": now, "ip": ip}
            self.dirty = True
            if now >= self.learning_until:
                self._raise(
                    f"new:{mac}", "new-device", "info", f"New device {ip}",
                    f"{mac} appeared on the network and claimed {ip}.", now, ip=ip, mac=mac,
                    hint="Open Network → Scans to see what it is.",
                )
        else:
            self.known[mac]["ip"] = ip

        held = self.bindings.get(ip)
        if held is None:
            self.bindings[ip] = {"mac": mac, "first": now, "last": now}
            self.dirty = True
        elif held["mac"] == mac:
            held["last"] = now
        else:
            previous = held["mac"]
            quiet = now - held["last"]
            self.bindings[ip] = {"mac": mac, "first": now, "last": now}
            self.dirty = True
            if ip == self.gateway:
                self._raise(
                    f"gw:{ip}:{mac}", "gateway-changed", "bad", "The gateway's address changed hands",
                    f"Your gateway {ip} is now answered by {mac}; it was {previous}. "
                    "If you replaced or reset the router that is expected; otherwise something on the network "
                    "is impersonating it (ARP spoofing) and can read the traffic of every device that believes it.",
                    now, ip=ip, mac=mac, previous=previous,
                    hint="Check which device has that MAC (Network → Scans). If you didn't change the router, treat this as an attack.",
                )
            elif quiet > IDLE_BINDING_SECONDS:
                self._raise(
                    f"moved:{ip}:{mac}", "address-reassigned", "info", f"{ip} went to a new device",
                    f"{ip} was {previous}, quiet for {int(quiet // 3600)}h, and is now {mac} — normally a lease handed to someone else.",
                    now, ip=ip, mac=mac, previous=previous,
                )
            else:
                self._raise(
                    f"conflict:{ip}:{mac}", "arp-conflict", "warn", f"{ip} is claimed by two devices",
                    f"{ip} was {previous} until moments ago and {mac} now claims it. Two devices share the address, a "
                    "laptop switched between Ethernet and Wi-Fi, or something is spoofing it.",
                    now, ip=ip, mac=mac, previous=previous,
                    hint="If a laptop moved between wired and Wi-Fi this clears itself; if it keeps flipping, find the second device.",
                )
        self._trim()

    # --- DHCP ------------------------------------------------------------------

    def observe_dhcp(self, message: dict, now: float) -> None:
        """A DHCP reply. Only servers speak Offer / ACK / NAK."""
        if message.get("type") not in ("Offer", "ACK", "NAK"):
            return
        server = message.get("server") or message.get("src")
        mac = message.get("eth")
        if not _interesting_ip(server):
            return
        seen = self.servers.get(server)
        if seen:
            seen["last"] = now
            if mac and _interesting_mac(mac):
                seen["mac"] = mac
            return
        others = {ip: info for ip, info in self.servers.items()}
        self.servers[server] = {"mac": mac, "first": now, "last": now}
        self.dirty = True
        if others:
            names = ", ".join(f"{ip} ({info.get('mac') or 'unknown MAC'})" for ip, info in sorted(others.items()))
            self._raise(
                f"dhcp:{server}", "second-dhcp-server", "warn", f"Another DHCP server is answering: {server}",
                f"{server} ({mac or 'unknown MAC'}) offered a lease; {names} has been answering until now. "
                "Two servers hand out conflicting addresses, and a rogue one can send every device to its own DNS.",
                now, ip=server, mac=mac,
                hint="If you meant to run two (a router and a Pi-hole, say), turn DHCP off on one; otherwise find and unplug the intruder.",
            )

    # --- reading it out --------------------------------------------------------

    def active(self, now: float) -> list[dict]:
        """Warnings and worse sighted recently — what the dashboard alerts on.
        Information (a new device) is listed but never alerts."""
        return [
            dict(f) for f in sorted(self.findings.values(), key=lambda f: f["last"], reverse=True)
            if f["severity"] != "info" and now - f["last"] <= ACTIVE_SECONDS
        ]

    def recent(self, limit: int = 100) -> list[dict]:
        return [dict(f) for f in sorted(self.findings.values(), key=lambda f: f["last"], reverse=True)[:limit]]

    def export(self) -> dict:
        return {"bindings": self.bindings, "known": self.known, "servers": self.servers}


# --- the controller ----------------------------------------------------------------

_lock = threading.RLock()
_enabled = False
_detector: Detector | None = None
_status: dict = {"state": "off", "iface": None, "since": None, "error": None, "beat": None}
_container = None
_thread: threading.Thread | None = None
# One flag per run, replaced on every enable: a supervisor that is still
# winding down from a disable must not be revived by the next enable.
_stop = threading.Event()
_last_save = 0.0


def _load() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(force: bool = False) -> None:
    global _last_save
    now = time.monotonic()
    with _lock:
        if _detector is None or (not force and (not _detector.dirty or now - _last_save < SAVE_EVERY)):
            return
        # Serialised while holding the lock: the watcher thread keeps changing
        # these tables, and encoding a dict that changes underneath raises.
        text = json.dumps({"enabled": _enabled, **_detector.export()})
        _detector.dirty = False
    _last_save = now
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(text)
        tmp.replace(STATE_FILE)
    except OSError as error:
        log.warning("netwatch: couldn't save its state: %s", error)
        with _lock:
            if _detector:
                _detector.dirty = True  # try again next time rather than forget it


def _launch(client, iface: str):
    """The watcher helper, with logging off (as the capture helper) and output
    read through an attach stream opened before the start."""
    container = client.containers.create(
        rebuild.helper_image(client),
        ["python", "/app/netwatch_worker.py"],
        network_mode="host",
        cap_drop=["ALL"],
        cap_add=["NET_RAW"],
        read_only=True,
        environment={"NETWATCH_CONFIG": json.dumps({"iface": iface})},
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


def _consume(stream, stop: threading.Event) -> str:
    """Feed the detector until the helper's output ends; why it ended."""
    tail: list[str] = []
    buffer = b""
    for chunk in stream:
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            if not handle(text):
                tail = [*tail, text[:300]][-STDERR_LINES:]
            if stop.is_set():
                return "stopped"
    return tail[-1] if tail else "the watcher stopped unexpectedly"


def handle(line: str) -> bool:
    """Apply one line from the helper. False if it wasn't ours."""
    try:
        msg = json.loads(line)
        kind = msg.get("t")
    except (ValueError, AttributeError):
        return False
    now = time.time()
    with _lock:
        detector = _detector
        if detector is None:
            return True
        try:
            if kind == "arp":
                detector.observe_arp(msg["ip"], msg["mac"], now)
            elif kind == "dhcp":
                detector.observe_dhcp(msg, now)
            elif kind == "beat":
                _status["beat"] = now
            elif kind == "end":
                _status["error"] = msg.get("reason")
            else:
                return False
        except (KeyError, TypeError, ValueError) as error:
            log.warning("netwatch: ignoring a malformed %s line: %s", kind, error)
    _save()  # rate-limited: what was learned survives a restart
    return True


def _supervise(client, stop: threading.Event) -> None:
    """Keep the helper running while the watch is on: relaunch with a growing
    pause if it dies, and keep the gateway the detector compares against fresh."""
    global _container
    failures = 0
    while not stop.is_set():
        started = time.monotonic()
        try:
            identity = lan_scan.identity(client)
            iface = identity.get("default")
            if not iface:
                raise RuntimeError("this host has no default route to watch")
            with _lock:
                if _detector:
                    _detector.gateway = identity.get("gateway")
            _clear_stale(client)
            container, stream = _launch(client, iface)
            with _lock:
                _container = container
                _status.update(state="watching", iface=iface, error=None, since=time.time(), beat=time.time())
            audit.info("network watch on %s started", iface)
            problem = _consume(stream, stop)
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001 - already gone
                pass
            if stop.is_set():
                break
        except Exception as error:  # noqa: BLE001 - reported in the status, then retried
            problem = str(error)
        # Only a failure gets here. One that came after a long healthy run is a
        # fresh start, not a loop; quick repeats back off.
        if time.monotonic() - started > 120:
            failures = 0
        failures += 1
        with _lock:
            _status.update(state="error", error=problem)
        log.warning("netwatch: %s", problem)
        if stop.wait(RESTART_BACKOFF[min(failures, len(RESTART_BACKOFF)) - 1]):
            break
        _save()
    with _lock:
        if _stop is stop:  # not already replaced by a newer run
            _status.update(state="off")


def _clear_stale(client) -> None:
    for old in client.containers.list(all=True, filters={"label": LABEL}):
        try:
            old.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def enable(client) -> dict:
    global _enabled, _detector, _thread, _stop
    with _lock:
        if _enabled and _thread and _thread.is_alive():
            return snapshot()
        _enabled = True
        _stop = threading.Event()
        if _detector is None:
            _detector = Detector(_load())
        _status.update(state="starting", error=None)
        _thread = threading.Thread(target=_supervise, args=(client, _stop), daemon=True)
        _thread.start()
        _detector.dirty = True
    _save(force=True)
    audit.info("network watch turned on")
    return snapshot()


def disable(client=None) -> dict:
    global _enabled
    with _lock:
        _enabled = False
        container = _container
    _stop.set()
    if container is not None:
        try:
            container.kill()
        except Exception:  # noqa: BLE001 - already stopped
            pass
    with _lock:
        _status.update(state="off", error=None)
        if _detector:
            _detector.dirty = True
    _save(force=True)
    audit.info("network watch turned off")
    return snapshot()


def resume(client) -> None:
    """Start again at agent startup if the watch was left on."""
    global _detector
    saved = _load()
    if saved.get("enabled"):
        with _lock:
            _detector = Detector(saved)
        enable(client)


def snapshot() -> dict:
    now = time.time()
    with _lock:
        detector = _detector
        learning = bool(detector and now < detector.learning_until)
        return {
            "enabled": _enabled,
            "state": _status["state"],
            "iface": _status["iface"],
            "since": _status["since"],
            "error": _status["error"],
            "beat": _status["beat"],
            "learning": learning,
            "learning_until": detector.learning_until if learning else None,
            "devices": len(detector.known) if detector else 0,
            "gateway": detector.gateway if detector else None,
            "dhcp_servers": [
                {"ip": ip, **info} for ip, info in sorted((detector.servers if detector else {}).items())
            ],
            "findings": detector.recent() if detector else [],
            "active": detector.active(now) if detector else [],
        }
