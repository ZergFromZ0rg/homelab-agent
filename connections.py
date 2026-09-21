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


def aggregate(flows: list[dict], limit: int) -> tuple[list[dict], int]:
    """Collapse flows onto the conversation they belong to.

    A browser opens six connections to the same host; a torrent client
    opens six hundred. Grouping by (protocol, both addresses, destination
    port) turns that back into one row per conversation, which is the unit
    someone reading this actually cares about.

    Deliberately *not* resolved into "local" and "remote" here. Which end
    is this host isn't knowable from the table alone, and guessing it from
    address ranges gets inbound LAN connections backwards. The endpoints
    are reported as conntrack sees them; naming the local side is what the
    container-attribution pass adds.
    """
    grouped: dict[tuple, dict] = {}

    for flow in flows:
        orig = flow["orig"]
        key = (flow["proto"], orig["src"], orig["dst"], orig["dport"])

        row = grouped.get(key)
        if row is None:
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
                # Filled in by the container-attribution pass; present now
                # so the dashboard's shape doesn't change under it.
                "container": None,
                "container_id": None,
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


_cache: dict = {"at": 0.0, "data": None}


def snapshot(host: str = "", *, now: float | None = None) -> dict:
    """What GET /connections returns. Never raises — an unreadable table is
    a reportable state, not an error."""
    now = time.time() if now is None else now

    cached = _cache["data"]
    if cached is not None and now - _cache["at"] < cache_seconds():
        return cached

    result = _build(host)
    _cache.update(at=now, data=result)
    return result


def _build(host: str) -> dict:
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

    peers, total = aggregate(flows, max_peers())

    return {
        **base,
        "available": True,
        "source": str(path),
        "accounting": has_accounting(flows),
        "flows_total": len(flows),
        "conversations_total": total,
        "truncated": total > len(peers),
        "peers": peers,
    }


def reset_cache() -> None:
    _cache.update(at=0.0, data=None)
