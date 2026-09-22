"""Who this host is actually talking to, read from the kernel's conntrack
table.

The dashboard can already show *how much* a host and each container send
and receive. It can't show *who to* — node_exporter reports counters, not
flows, and Docker's per-container stats are totals. This module fills that
in by parsing ``/proc/net/nf_conntrack``: one line per tracked flow, with
both endpoints and (when the kernel is asked nicely) per-direction byte
counts.

Two things have to be true on the host, and neither is the default:

1. **The table has to be reachable.** conntrack is per network namespace,
   and the agent runs in its own, where the table is all but empty. Mount
   the host's in — narrowest first::

       -v /proc/net/nf_conntrack:/host/nf_conntrack:ro

   If that comes back empty on your kernel, mount the host's procfs and
   read init's namespace instead (what node_exporter does), accepting that
   it exposes every host process's cmdline and environ to this container::

       -v /proc:/host/proc:ro          # then CONNTRACK_FILE=/host/proc/1/net/nf_conntrack

2. **Byte accounting has to be on**, or the rows carry no ``bytes=`` at
   all and you get flows without volume::

       sysctl -w net.netfilter.nf_conntrack_acct=1

``snapshot()`` reports which of these is missing rather than failing, so
the dashboard can say what to turn on instead of showing an error.

Env knobs (all optional):
  CONNECTIONS_ENABLED   "0" turns the endpoint off entirely; some hosts
                        shouldn't collect this at all. Default on.
  CONNTRACK_FILE        explicit path, tried before the defaults below.
  CONNECTIONS_MAX_PEERS how many rows to return (default 50). The rest are
                        still counted, just not listed.
  CONNECTIONS_CACHE     seconds to reuse a parse (default 5). A busy host
                        can carry tens of thousands of flows; the /ws loop
                        polls far faster than this table is worth re-reading.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import sockets
from log import log

# This container's own conntrack table. It exists and is readable, but in
# the agent's network namespace it is all but empty — so finding it here is
# only meaningful when the agent runs with the host's networking. Tried
# last, and an empty result from it is reported as "not set up" rather than
# "nothing is happening", because the two are indistinguishable otherwise.
OWN_NAMESPACE_PATH = "/proc/net/nf_conntrack"


def default_paths() -> tuple[str, ...]:
    """Where to look, in preference order.

    Note the middle two: if the agent already has the host filesystem
    mounted for the **backup** feature (``-v /:/host:ro``, HOST_ROOT), then
    the host's table is *already* in this container and nothing further
    needs mounting. It has to be addressed as PID 1's copy — ``/proc/net``
    is a symlink to ``/proc/self/net``, so a bind-mounted ``/host/proc/net``
    would resolve back to this process's namespace and hand us the empty
    table again.
    """
    host_root = os.getenv("HOST_ROOT", "/host").rstrip("/") or "/host"

    return (
        # The narrow, purpose-made mount.
        "/host/nf_conntrack",
        # Free if the backup feature's host mount is already there.
        f"{host_root}/proc/1/net/nf_conntrack",
        "/host/proc/1/net/nf_conntrack",
        OWN_NAMESPACE_PATH,
    )

L4_PROTOCOLS = {
    "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "udplite", "gre", "unknown",
}

# "src=10.0.0.5" / "bytes=1440" / "dport=443". Values never contain spaces.
_FIELD_RE = re.compile(r"([a-z_]+)=(\S+)")

# A bare connection state, e.g. ESTABLISHED, TIME_WAIT, SYN_SENT. Bracketed
# tokens ([ASSURED], [UNREPLIED]) are flags, not states.
_STATE_RE = re.compile(r"^[A-Z][A-Z_]+$")


def enabled() -> bool:
    return os.getenv("CONNECTIONS_ENABLED", "1").strip() not in ("0", "false", "no")


def max_peers() -> int:
    try:
        return max(1, int(os.getenv("CONNECTIONS_MAX_PEERS", "50")))
    except ValueError:
        return 50


def cache_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("CONNECTIONS_CACHE", "5")))
    except ValueError:
        return 5.0


def source_path() -> Path | None:
    """The first conntrack table we can actually read, or None."""
    candidates = [os.getenv("CONNTRACK_FILE", "").strip(), *default_paths()]

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        try:
            if path.exists() and os.access(path, os.R_OK):
                return path
        except OSError:
            continue

    return None


def parse_line(line: str) -> dict | None:
    """One conntrack row -> a flow, or None if it isn't one we understand.

    The format is positional at the front and key=value after it::

        ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 \\
            sport=51234 dport=443 packets=12 bytes=1440 \\
            src=1.1.1.1 dst=10.0.0.5 sport=443 dport=51234 \\
            packets=10 bytes=5000 [ASSURED] mark=0 use=1

    The tuple appears twice: the direction the connection was opened in
    ("orig"), then the return path ("reply"). UDP rows carry no state,
    ICMP rows carry type/code/id instead of ports, an unanswered flow is
    marked [UNREPLIED] and has no reply counters, and with accounting off
    the packets=/bytes= pairs are missing everywhere.
    """
    tokens = line.split()
    if not tokens:
        return None

    proto = next((t for t in tokens[:4] if t in L4_PROTOCOLS), None)
    if proto is None:
        return None

    family = "ipv6" if tokens[0] == "ipv6" else "ipv4"

    # Everything before the first src= is positional; the state, if the
    # protocol has one, is the bare uppercase word in there.
    head = line.split("src=", 1)[0].split()
    state = next((t for t in head if _STATE_RE.match(t)), None)

    # Fields in order, so the first src/dst/sport/... is the original
    # direction and the second is the reply.
    fields: dict[str, list[str]] = {}
    for key, value in _FIELD_RE.findall(line):
        fields.setdefault(key, []).append(value)

    sources = fields.get("src", [])
    destinations = fields.get("dst", [])
    if not sources or not destinations:
        return None

    def nth(key: str, index: int) -> str | None:
        values = fields.get(key, [])
        return values[index] if len(values) > index else None

    def count(key: str, index: int) -> int | None:
        value = nth(key, index)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def port(key: str, index: int) -> int | None:
        return count(key, index)

    return {
        "family": family,
        "proto": proto,
        "state": state,
        "unreplied": "[UNREPLIED]" in tokens,
        "orig": {
            "src": sources[0],
            "dst": destinations[0],
            "sport": port("sport", 0),
            "dport": port("dport", 0),
            "bytes": count("bytes", 0),
            "packets": count("packets", 0),
        },
        "reply": {
            "src": nth("src", 1),
            "dst": nth("dst", 1),
            "sport": port("sport", 1),
            "dport": port("dport", 1),
            "bytes": count("bytes", 1),
            "packets": count("packets", 1),
        },
    }


def parse(text: str) -> list[dict]:
    flows = []

    for line in text.splitlines():
        flow = parse_line(line)
        if flow is not None:
            flows.append(flow)

    return flows


def has_accounting(flows: list[dict]) -> bool:
    """Whether the kernel is counting bytes. One accounted flow is enough —
    an idle table of zero flows says nothing either way, so that reads as
    "no" and the caller can suggest the sysctl."""
    return any(flow["orig"]["bytes"] is not None for flow in flows)


def aggregate(flows: list[dict], limit: int, index: dict | None = None) -> tuple[list[dict], int]:
    """Collapse flows onto the conversation they belong to.

    A browser opens six connections to the same host; a torrent client
    opens six hundred. Grouping by (protocol, both addresses, destination
    port) turns that back into one row per conversation, which is the unit
    someone reading this actually cares about.

    The endpoints stay as conntrack recorded them — ``src`` opened the
    connection — because that is a fact about the flow rather than about
    this host. ``attribute`` adds the host's own view on top when it can
    recognise one end as a container: ``direction``, ``peer``, and
    ``rx_bytes``/``tx_bytes`` the right way round. Without an ``index``
    (or for flows that belong to no container) those stay null.
    """
    grouped: dict[tuple, dict] = {}

    empty_attribution = {
        "container": None, "container_id": None, "peer_container": None,
        "direction": None, "peer": None, "peer_port": None,
        "rx_bytes": None, "tx_bytes": None,
    }

    for flow in flows:
        orig = flow["orig"]
        key = (flow["proto"], orig["src"], orig["dst"], orig["dport"])

        row = grouped.get(key)
        if row is None:
            # Attribution depends only on the key, so it's the same for
            # every flow in a group — work it out once.
            attributed = attribute(flow, index) if index else dict(empty_attribution)

            row = grouped[key] = {
                "proto": flow["proto"],
                "family": flow["family"],
                "src": orig["src"],
                "dst": orig["dst"],
                "dport": orig["dport"],
                "flows": 0,
                "orig_bytes": None,
                "reply_bytes": None,
                "orig_packets": None,
                "reply_packets": None,
                "states": set(),
                **{k: v for k, v in attributed.items() if not k.endswith("_bytes")},
                "rx_bytes": None,
                "tx_bytes": None,
                # Filled in for unattributed rows from the socket tables.
                "process": None,
                "pid": None,
                # One representative flow, for the socket lookup. Every
                # flow in a group shares the key it matches on. Stripped
                # before the row leaves this module.
                "_flow": flow,
            }

        row["flows"] += 1
        if flow["state"]:
            row["states"].add(flow["state"])

        for side, prefix in (("orig", "orig"), ("reply", "reply")):
            for field in ("bytes", "packets"):
                value = flow[side][field]
                if value is None:
                    continue
                current = row[f"{prefix}_{field}"]
                row[f"{prefix}_{field}"] = value if current is None else current + value

        if row["direction"]:
            # Same swap as attribute(), applied to the running totals.
            sent, received = (
                (flow["orig"]["bytes"], flow["reply"]["bytes"])
                if row["direction"] == "out"
                else (flow["reply"]["bytes"], flow["orig"]["bytes"])
            )
            for field, value in (("tx_bytes", sent), ("rx_bytes", received)):
                if value is None:
                    continue
                current = row[field]
                row[field] = value if current is None else current + value

    rows = list(grouped.values())
    for row in rows:
        row["states"] = sorted(row["states"])

    # Loudest first. With accounting off there are no bytes to sort on, so
    # fall back to how many connections the conversation is holding open.
    rows.sort(
        key=lambda r: (
            (r["orig_bytes"] or 0) + (r["reply_bytes"] or 0),
            r["flows"],
        ),
        reverse=True,
    )

    return rows[:limit], len(rows)


def container_map(client) -> list[dict]:
    """Every container's addresses and published ports, which is all the
    attribution below needs. Read straight from the daemon rather than the
    agent's container cache so ``GET /containers`` keeps its payload."""
    containers = []

    for container in client.containers.list():
        try:
            settings = container.attrs.get("NetworkSettings") or {}

            ips = {
                network.get("IPAddress")
                for network in (settings.get("Networks") or {}).values()
                if network and network.get("IPAddress")
            }
            if settings.get("IPAddress"):  # legacy single-network shape
                ips.add(settings["IPAddress"])

            containers.append({
                "id": container.short_id,
                "name": container.name,
                "ips": sorted(ips),
                "ports": _published_ports(container),
            })

        except Exception as error:  # noqa: BLE001 - one bad container
            log.debug("connection attribution skipped %s: %s", container.name, error)

    return containers


def _published_ports(container) -> dict:
    """``{(host_port, proto): True}`` for everything this container
    publishes to the host."""
    host_config = container.attrs.get("HostConfig") or {}
    published = {}

    for target, bindings in (host_config.get("PortBindings") or {}).items():
        proto = target.split("/")[-1] if "/" in target else "tcp"
        for binding in bindings or []:
            port = binding.get("HostPort")
            if port:
                try:
                    published[(int(port), proto)] = True
                except ValueError:
                    continue

    return published


def build_index(containers: list[dict]) -> dict:
    """Two lookups: container IP -> container, and published (port, proto)
    -> container."""
    by_ip, by_port = {}, {}

    for container in containers:
        entry = {"container": container["name"], "container_id": container["id"]}
        for ip in container.get("ips") or []:
            by_ip[ip] = entry
        for key in container.get("ports") or {}:
            by_port[key] = entry

    return {"by_ip": by_ip, "by_port": by_port}


def attribute(flow: dict, index: dict) -> dict:
    """Work out which container a flow belongs to, and with that, which end
    of it is this host.

    Docker rewrites addresses in both directions, and the rewrite is the
    signal:

    * **outbound** (container to the world) is masqueraded, so the original
      source is still the container's own address.
    * **inbound** (the world to a published port) is DNAT'd, so the
      container's address appears as the *reply's* source — the original
      destination is the host.

    Matching a published host port catches the inbound case on setups where
    the reply tuple doesn't carry the container address.

    Knowing which end is the container is also what makes ``rx``/``tx``
    meaningful: conntrack counts bytes per direction of the *connection*,
    not of the host, so the two are swapped for an inbound flow.
    """
    orig, reply = flow["orig"], flow["reply"]
    by_ip, by_port = index["by_ip"], index["by_port"]

    local = by_ip.get(orig["src"])
    if local:
        direction = "out"
        peer, peer_port = orig["dst"], orig["dport"]
        tx, rx = orig["bytes"], reply["bytes"]
    else:
        local = by_ip.get(reply["src"]) or by_port.get((orig["dport"], flow["proto"]))
        if local:
            direction = "in"
            peer, peer_port = orig["src"], orig["dport"]
            rx, tx = orig["bytes"], reply["bytes"]
        else:
            return {
                "container": None,
                "container_id": None,
                "peer_container": None,
                "direction": None,
                "peer": None,
                "peer_port": None,
                "rx_bytes": None,
                "tx_bytes": None,
            }

    # Container to container on a shared network — name both ends.
    other = by_ip.get(orig["dst"] if direction == "out" else orig["src"])

    return {
        "container": local["container"],
        "container_id": local["container_id"],
        "peer_container": other["container"] if other else None,
        "direction": direction,
        "peer": peer,
        "peer_port": peer_port,
        "rx_bytes": rx,
        "tx_bytes": tx,
    }


_cache: dict = {"at": 0.0, "data": None}


def snapshot(host: str = "", client=None, *, now: float | None = None) -> dict:
    """What GET /connections returns. Never raises — an unreadable table is
    a reportable state, not an error."""
    now = time.time() if now is None else now

    cached = _cache["data"]
    if cached is not None and now - _cache["at"] < cache_seconds():
        return cached

    result = _build(host, client)
    _cache.update(at=now, data=result)
    return result


def _name_host_processes(peers: list[dict]) -> str:
    """Fill in ``process``/``pid`` on the rows no container claimed.

    Mutates ``peers`` and returns what happened, because "nothing got
    named" has three very different causes and only one of them is fine:

      ``ok``        it ran (whether or not every socket resolved)
      ``off``       CONNECTIONS_PROCESSES=0
      ``no-sockets``  the socket tables weren't readable
      ``denied``    the walk was refused — the container is missing
                    CAP_SYS_PTRACE, so it can't see who owns a socket

    ``denied`` used to be indistinguishable from "these sockets have no
    owner", which made the whole feature look like it worked while naming
    nothing at all.
    """
    if not sockets.enabled():
        return "off"

    unclaimed = [p for p in peers if not p.get("container")]
    if not unclaimed:
        return "ok"

    try:
        index = sockets.build_index(sockets.read_sockets())
        if not index["by_port"]:
            return "no-sockets"

        wanted, per_row = set(), {}
        for row in unclaimed:
            inode = sockets.match(row["_flow"], index)
            if inode is not None:
                per_row[id(row)] = inode
                wanted.add(inode)

        found, denied = sockets.owners(wanted)

        for row in unclaimed:
            owner = found.get(per_row.get(id(row)))
            if owner:
                row["process"] = owner["process"]
                row["pid"] = owner["pid"]

        if found:
            return "ok"
        # Sockets were read and the walk wasn't refused, yet nothing
        # resolved. That's a real state and it deserves its own name —
        # reporting it as "ok" is what made this look like it worked.
        return "denied" if denied else "unmatched"

    except OSError as error:
        log.debug("process names unavailable: %s", error)
        return "no-sockets"


def _build(host: str, client=None) -> dict:
    base = {"host": host, "updated_at": time.time(), "available": False}

    if not enabled():
        return {**base, "reason": "disabled by CONNECTIONS_ENABLED=0"}

    path = source_path()
    if path is None:
        return {
            **base,
            "reason": (
                "conntrack table not readable — mount the host's in "
                "(-v /proc/net/nf_conntrack:/host/nf_conntrack:ro) or set "
                "CONNTRACK_FILE"
            ),
        }

    try:
        text = path.read_text(errors="replace")
    except OSError as error:
        log.warning("conntrack read failed (%s): %s", path, error)
        return {**base, "reason": f"could not read {path}: {error}"}

    flows = parse(text)

    # Falling back to this container's own table and finding it empty means
    # one of two things, and we can't tell which: the agent isn't sharing
    # the host's network namespace (overwhelmingly likely), or the host
    # genuinely has no tracked flows. Reporting "0 conversations" would
    # look like a working feature on a quiet host, so say it isn't set up.
    if str(path) == OWN_NAMESPACE_PATH and not flows:
        return {
            **base,
            "reason": (
                "conntrack table is empty here — the agent has its own "
                "network namespace, so mount the host's table in "
                "(-v /proc/net/nf_conntrack:/host/nf_conntrack:ro). Already "
                "mounting the host filesystem for backups? Then it's found "
                "automatically and this means the host really has no "
                "tracked flows."
            ),
        }

    index = None
    if client is not None:
        try:
            index = build_index(container_map(client))
        except Exception as error:  # noqa: BLE001 - attribution is a bonus
            log.warning("container attribution unavailable: %s", error)

    peers, total = aggregate(flows, max_peers(), index)
    processes = _name_host_processes(peers)
    for row in peers:
        row.pop("_flow", None)

    hint = None
    facts = None

    if processes in ("denied", "unmatched", "no-sockets"):
        # Collect the evidence once, here, rather than leaving someone to
        # work it out by hand across several machines.
        facts = sockets.diagnose()
        hint = facts.get("reason") or (
            "Host processes couldn't be matched to their sockets on this "
            f"host — {facts['pids_visible']} processes visible, "
            f"{facts['fds_readable']} with readable sockets, "
            f"{facts['sockets']} sockets in the table. Container traffic "
            "is named regardless; this only affects the host's own."
        )

    return {
        **base,
        "available": True,
        "processes_hint": hint,
        "processes_facts": facts,
        "source": str(path),
        "accounting": has_accounting(flows),
        "flows_total": len(flows),
        "conversations_total": total,
        "truncated": total > len(peers),
        "attributed": index is not None,
        "processes": processes == "ok",
        "processes_state": processes,
        "peers": peers,
    }


def reset_cache() -> None:
    _cache.update(at=0.0, data=None)
