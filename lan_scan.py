"""Find what is on this host's LAN, live.

``POST /network/scan`` starts a sweep of the subnet the host is on; ``GET
/network/scan`` returns the job as it stands, devices appearing as they are
found. Meant for "what is on my network, and is that new?" — on the user's
own homelab, from the user's own agent.

How it works, and why it needs no extra privileges or packages:

1. A throwaway container on the **host's network** reads the host's
   interfaces (address and mask) and its ARP table, in one go. The agent
   itself sits behind Docker's bridge, where neither is visible.
2. The agent walks every address in the subnet with plain TCP connects. A
   connect that is *accepted* or *refused* proves the host is there; only
   a silence proves nothing. Traffic leaves through the host's NAT, so the
   host ARPs for everything it talks to…
3. …which is why a second read of the host's ARP table afterwards names the
   MAC of every neighbour, including the ones that dropped every probe.
4. Hosts that answered get a short port scan and a reverse-DNS try.

Hard limits, because this is an active scanner: only private ranges, nothing
wider than a /22, one scan at a time, and a few common ports per host — not
a port scanner for somewhere else's network.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

import rebuild
from log import audit, log

MAX_HOSTS = 1024
PROBE_TIMEOUT = 0.4
PORT_TIMEOUT = 0.5
WORKERS = 96
HELPER_TIMEOUT = 60

# Tried in order until one answers or refuses; any reply at all means "alive".
LIVENESS_PORTS = (80, 443, 22, 445, 53, 8080, 139, 3389, 62078)
# What a live host is asked about.
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    548: "afp", 631: "ipp", 1883: "mqtt", 2049: "nfs", 3000: "http",
    3306: "mysql", 3389: "rdp", 5000: "http", 5432: "postgres", 5900: "vnc",
    8000: "http", 8080: "http", 8096: "jellyfin", 8123: "agent", 8443: "https",
    8989: "sonarr", 9000: "http", 9090: "http", 9100: "printer", 32400: "plex",
    51820: "wireguard",
}
SKIP_IFACE = ("lo", "docker", "br-", "veth", "virbr", "tailscale", "wg", "tun")

_HELPER_SCRIPT = r"""
import fcntl, json, os, socket, struct
def addr(name, req):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), req, struct.pack('256s', name[:15].encode()))[20:24])
    except OSError:
        return None
out = {"ifaces": [], "arp": [], "default": None}
try:
    for line in open('/proc/net/route').read().splitlines()[1:]:
        f = line.split()
        if f[1] == '00000000':
            out['default'] = f[0]
            break
except OSError:
    pass
for name in sorted(os.listdir('/sys/class/net')):
    ip, mask = addr(name, 0x8915), addr(name, 0x891b)
    if ip and mask:
        out['ifaces'].append({'name': name, 'ip': ip, 'mask': mask})
for line in open('/proc/net/arp').read().splitlines()[1:]:
    f = line.split()
    if len(f) >= 6:
        out['arp'].append({'ip': f[0], 'flags': f[2], 'mac': f[3], 'dev': f[5]})
print(json.dumps(out))
"""

_lock = threading.RLock()
_job: dict | None = None


class ScanError(Exception):
    pass


# --- reading the host --------------------------------------------------------


def read_host(client) -> dict:
    """The host's interfaces and ARP table, via a throwaway host-network container."""
    try:
        out = client.containers.run(
            rebuild.helper_image(client),
            ["python", "-c", _HELPER_SCRIPT],
            network_mode="host",
            remove=True,
            labels={"homelab-agent-lanscan": "1"},
        )
    except Exception as error:  # noqa: BLE001 - reported to the user as-is
        raise ScanError(f"couldn't read the host's network: {error}") from error
    try:
        return json.loads(out.decode("utf-8", "replace").strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise ScanError("the host's network report was unreadable") from error


def choose_network(host: dict, iface: str | None = None) -> tuple[str, ipaddress.IPv4Network, str]:
    """(interface, network, host's own address) to scan, or ScanError."""
    candidates = []
    for i in host.get("ifaces", []):
        name = i["name"]
        if name.startswith(SKIP_IFACE) and name != iface:
            continue
        try:
            net = ipaddress.ip_network(f"{i['ip']}/{i['mask']}", strict=False)
        except ValueError:
            continue
        if net.version != 4 or not net.is_private:
            continue
        candidates.append((name, net, i["ip"]))
    if iface:
        candidates = [c for c in candidates if c[0] == iface]
    if not candidates:
        raise ScanError("no private LAN interface to scan on this host")
    candidates.sort(key=lambda c: c[0] != host.get("default"))
    name, net, own = candidates[0]
    if net.num_addresses - 2 > MAX_HOSTS:
        raise ScanError(f"{net} is larger than a /22 — refusing to sweep it")
    return name, net, own


# --- probing -----------------------------------------------------------------


def probe(ip: str) -> bool:
    """True when ``ip`` accepted or refused a connection — it's there."""
    for port in LIVENESS_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PROBE_TIMEOUT)
        try:
            code = s.connect_ex((ip, port))
        except OSError:
            code = -1
        finally:
            s.close()
        if code in (0, 111, 61, 10061):  # open, refused (Linux / macOS / Windows)
            return True
    return False


def open_ports(ip: str) -> list[dict]:
    found = []
    for port, name in SERVICES.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        try:
            if s.connect_ex((ip, port)) == 0:
                found.append({"port": port, "service": name})
        except OSError:
            pass
        finally:
            s.close()
    return found


def hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def arp_macs(host: dict, net: ipaddress.IPv4Network) -> dict[str, str]:
    macs = {}
    for e in host.get("arp", []):
        try:
            if ipaddress.ip_address(e["ip"]) not in net:
                continue
        except ValueError:
            continue
        # flags 0x2 = complete; 00:00:… is an unanswered request.
        if int(e.get("flags", "0x0"), 16) & 0x2 and e.get("mac") not in (None, "00:00:00:00:00:00"):
            macs[e["ip"]] = e["mac"]
    return macs


# --- the job -----------------------------------------------------------------


def _fresh(net, iface, own) -> dict:
    return {
        "state": "scanning",
        "subnet": str(net),
        "iface": iface,
        "own_ip": own,
        "phase": "sweeping",
        "total": net.num_addresses - 2,
        "scanned": 0,
        "devices": [],
        "started_at": time.time(),
        "finished_at": None,
        "error": None,
    }


def _upsert(job, ip, **fields):
    for d in job["devices"]:
        if d["ip"] == ip:
            d.update(fields)
            return
    job["devices"].append({"ip": ip, "mac": None, "hostname": None, "ports": None, **fields})


def _run(client, job, net, own, host_before):
    try:
        addrs = [str(a) for a in net.hosts()]
        with ThreadPoolExecutor(WORKERS) as pool:
            futures = {pool.submit(probe, ip): ip for ip in addrs}
            pending = set(futures)
            while pending:
                done, pending = wait(pending, timeout=0.3)
                with _lock:
                    for f in done:
                        job["scanned"] += 1
                        if f.result():
                            _upsert(job, futures[f], via="tcp")

        job["phase"] = "arp"
        macs = arp_macs(read_host(client), net)
        with _lock:
            known = {d["ip"] for d in job["devices"]}
            for ip, mac in macs.items():
                # Found by TCP already: just add the MAC. Otherwise the
                # neighbour table is the only thing that saw it.
                _upsert(job, ip, mac=mac, **({} if ip in known else {"via": "arp"}))
            if own and not any(d["ip"] == own for d in job["devices"]):
                _upsert(job, own, via="self")

        job["phase"] = "ports"
        with ThreadPoolExecutor(WORKERS // 2) as pool:
            ips = [d["ip"] for d in job["devices"]]
            port_f = {pool.submit(open_ports, ip): ip for ip in ips}
            name_f = {pool.submit(hostname, ip): ip for ip in ips}
            for f in port_f:
                ip = port_f[f]
                with _lock:
                    _upsert(job, ip, ports=f.result())
            done, _ = wait(set(name_f), timeout=4)
            with _lock:
                for f in done:
                    _upsert(job, name_f[f], hostname=f.result())
        with _lock:
            job["state"] = "done"
            job["phase"] = "done"
            job["finished_at"] = time.time()
        audit.info("lan scan of %s found %d devices", net, len(job["devices"]))
    except Exception as error:  # noqa: BLE001 - surfaced in the job
        log.warning("lan scan failed: %s", error)
        with _lock:
            job["state"] = "error"
            job["error"] = str(error)
            job["finished_at"] = time.time()


def start(client, iface: str | None = None) -> dict:
    """Begin a sweep (or report the one already running)."""
    global _job
    with _lock:
        if _job and _job["state"] == "scanning":
            return snapshot()
    host = read_host(client)
    name, net, own = choose_network(host, iface)
    job = _fresh(net, name, own)
    with _lock:
        _job = job
    audit.info("lan scan of %s started", net)
    threading.Thread(target=_run, args=(client, job, net, own, host), daemon=True).start()
    return snapshot()


def snapshot() -> dict:
    with _lock:
        if _job is None:
            return {"state": "idle", "devices": []}
        out = dict(_job)
        out["devices"] = [dict(d) for d in _job["devices"]]
        return out
