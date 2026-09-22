"""Which process owns a socket, for the connections that belong to no
container.

``connections.py`` names the container behind a flow by recognising
Docker's own NAT. That leaves everything the *host* itself is doing —
sshd, the package manager, a cron job, node_exporter — as bare addresses.
This module fills those in from the kernel's socket tables.

Two reads, joined on the socket inode:

* ``/proc/net/{tcp,tcp6,udp,udp6}`` — one line per socket, with the local
  and remote address and the inode backing it.
* ``/proc/<pid>/fd/*`` — symlinks reading ``socket:[12345]`` for each
  socket a process holds, and ``/proc/<pid>/comm`` for its name.

**No ``pid: host`` is needed.** Both come from the host filesystem mount
the backup feature already asks for (``-v /:/host:ro``): a bind-mounted
procfs exposes every host PID regardless of this container's own PID
namespace, and reading an fd symlink is just a readlink. As with
conntrack, the socket tables have to be addressed as PID 1's copy —
``/proc/net`` is a symlink to ``/proc/self/net`` and would otherwise
resolve to this container's empty tables.

The fd scan walks every process's open files, so it only runs when there
are unattributed flows to name, and its result is cached with the
snapshot that asked for it.

  CONNECTIONS_PROCESSES  "0" skips all of this. Default on.
"""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

from log import log

# Only sockets in these states are worth naming. A listener with no peer
# has no flow to match, and a closing socket's inode is already gone.
TCP_ESTABLISHED = "01"

# Cap the fd walk on a host with thousands of processes; past this the
# answer isn't worth the syscalls.
MAX_PROCESSES = 2000


def enabled() -> bool:
    return os.getenv("CONNECTIONS_PROCESSES", "1").strip() not in ("0", "false", "no")


def proc_root() -> str:
    """Where the host's /proc is. Mirrors the conntrack lookup: the
    explicit override, then the backup feature's mount, then our own."""
    override = os.getenv("HOST_PROC", "").strip()
    if override:
        return override.rstrip("/")

    host_root = os.getenv("HOST_ROOT", "/host").rstrip("/") or "/host"

    for candidate in (f"{host_root}/proc", "/host/proc", "/proc"):
        if Path(candidate, "1").is_dir():
            return candidate

    return "/proc"


def parse_address(field: str) -> tuple[str | None, int | None]:
    """``"0100007F:1F90"`` -> ``("127.0.0.1", 8080)``.

    The kernel prints each 32-bit word of the address in host byte order,
    which on every platform this runs on is little-endian — so an IPv4
    address comes out byte-reversed, and an IPv6 one reversed within each
    of its four words.
    """
    raw, _, port_hex = field.partition(":")

    try:
        port = int(port_hex, 16)
    except ValueError:
        return None, None

    try:
        if len(raw) == 8:
            packed = struct.pack("<I", int(raw, 16))
            return socket.inet_ntop(socket.AF_INET, packed), port

        if len(raw) == 32:
            words = [raw[i : i + 8] for i in range(0, 32, 8)]
            packed = b"".join(struct.pack("<I", int(word, 16)) for word in words)
            return socket.inet_ntop(socket.AF_INET6, packed), port

    except (ValueError, OSError):
        pass

    return None, port


def parse_socket_table(text: str, proto: str) -> list[dict]:
    """One ``/proc/net/{tcp,udp}`` table into socket rows.

    Columns: ``sl local_address rem_address st tx:rx tr:when retrnsmt uid
    timeout inode``. Only the addresses, the state and the inode matter.
    """
    rows = []

    for line in text.splitlines()[1:]:  # first line is the header
        fields = line.split()
        if len(fields) < 10:
            continue

        # UDP has no meaningful connection state; TCP only gives us a
        # matchable peer once established.
        if proto == "tcp" and fields[3] != TCP_ESTABLISHED:
            continue

        try:
            inode = int(fields[9])
        except ValueError:
            continue

        if inode == 0:
            continue

        local_ip, local_port = parse_address(fields[1])
        remote_ip, remote_port = parse_address(fields[2])

        if local_port is None:
            continue

        rows.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "inode": inode,
        })

    return rows


def read_sockets(root: str | None = None) -> list[dict]:
    root = root or proc_root()
    rows = []

    for name, proto in (
        ("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")
    ):
        path = Path(root, "1", "net", name)
        try:
            rows.extend(parse_socket_table(path.read_text(), proto))
        except OSError as error:
            log.debug("socket table %s unreadable: %s", path, error)

    return rows


def _socket_inodes(pid_dir: Path) -> tuple[set[int], bool]:
    """The socket inodes one process holds open, and whether we were
    refused.

    Refusal is the common case and it matters: reading another process's
    ``/proc/<pid>/fd`` needs ptrace-level access, which Docker drops
    (``CAP_SYS_PTRACE``) by default. Treating that as "this process holds
    no sockets" is how the whole feature can look like it works while
    never naming anything.
    """
    inodes = set()

    try:
        entries = list((pid_dir / "fd").iterdir())
    except PermissionError:
        return inodes, True
    except OSError:
        # Gone between listing and reading.
        return inodes, False

    denied = False

    for entry in entries:
        try:
            target = os.readlink(entry)
        except PermissionError:
            denied = True
            continue
        except OSError:
            continue

        if target.startswith("socket:["):
            try:
                inodes.add(int(target[8:-1]))
            except ValueError:
                continue

    return inodes, denied


def owners(wanted: set[int], root: str | None = None) -> tuple[dict[int, dict], bool]:
    """``(inode -> {"pid", "process"}, denied)`` for the inodes asked for.

    Walks every process's open files, which is the expensive part — call
    it only with inodes you actually need, and stop as soon as they're all
    accounted for.

    ``denied`` says the walk was refused for most of what it tried, which
    means the container lacks ``CAP_SYS_PTRACE`` rather than that nothing
    owns these sockets.
    """
    if not wanted:
        return {}, False

    root = root or proc_root()
    found: dict[int, dict] = {}
    scanned = 0
    refused = 0

    try:
        entries = sorted(Path(root).iterdir())
    except OSError as error:
        log.debug("cannot list %s: %s", root, error)
        return {}, False

    for entry in entries:
        if not entry.name.isdigit():
            continue

        scanned += 1
        if scanned > MAX_PROCESSES:
            log.debug("process scan stopped at %d processes", MAX_PROCESSES)
            break

        inodes, denied = _socket_inodes(entry)
        refused += 1 if denied else 0

        matched = inodes & wanted
        if not matched:
            continue

        try:
            name = (entry / "comm").read_text().strip()
        except OSError:
            name = None

        for inode in matched:
            found[inode] = {"pid": int(entry.name), "process": name}

        if len(found) == len(wanted):
            break

    # A couple of refusals are normal (processes come and go). Being
    # refused by most of them is the capability problem.
    denied = scanned > 0 and refused > scanned / 2

    return found, denied


def build_index(sockets: list[dict]) -> dict:
    """Two lookups onto a socket inode: the exact four-tuple, and the
    local port alone as a fallback for when the peer doesn't line up (a
    UDP socket that has talked to several)."""
    exact, by_port = {}, {}

    for row in sockets:
        key = (row["proto"], row["local_port"], row["remote_ip"], row["remote_port"])
        exact.setdefault(key, row["inode"])
        by_port.setdefault((row["proto"], row["local_port"]), row["inode"])

    return {"exact": exact, "by_port": by_port}


def match(flow: dict, index: dict) -> int | None:
    """The inode of the socket behind an unattributed flow, if any.

    A flow this host opened has its local port in ``orig.sport``; one it
    accepted has it in ``orig.dport``. Try the full four-tuple each way
    before falling back to the port.
    """
    proto = flow["proto"]
    orig = flow["orig"]

    candidates = (
        # Outbound: we are the source.
        ((proto, orig["sport"], orig["dst"], orig["dport"]), (proto, orig["sport"])),
        # Inbound: we are the destination.
        ((proto, orig["dport"], orig["src"], orig["sport"]), (proto, orig["dport"])),
    )

    for exact_key, port_key in candidates:
        if exact_key[1] is None:
            continue
        inode = index["exact"].get(exact_key)
        if inode is not None:
            return inode

    for _, port_key in candidates:
        if port_key[1] is None:
            continue
        inode = index["by_port"].get(port_key)
        if inode is not None:
            return inode

    return None
