"""The network watcher's sniffer. Runs in a throwaway helper container on the
host's network (see netwatch.py), like the capture worker but far narrower.

It looks at exactly two kinds of frame, and the kernel does the choosing: a
classic-BPF filter attached to the socket passes ARP and IPv4 UDP on ports
67/68 (DHCP) and nothing else, so the Python side never sees ordinary traffic.
That is what makes it reasonable to leave running. What it reads out of those
frames is who claims which address and who hands out leases; it keeps no
packet, and prints one JSON line per *change* (the same claim is repeated at
most every ``REPEAT_SECONDS``):

  {"t": "arp", "ip": ..., "mac": ..., "op": 1|2, "eth": ...}
  {"t": "dhcp", "type": "Offer", "server": ..., "src": ..., "eth": ..., ...}
  {"t": "beat", "ts": ...}     every 10 s, so the controller knows it is alive
  {"t": "end", "reason": ...}  the last line

VLAN-tagged frames are not matched (the filter looks at fixed offsets).
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import struct
import sys
import time
import traceback

import capture_worker

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
REPEAT_SECONDS = 30  # an unchanged claim is passed on this often, not per packet
BEAT_SECONDS = 10
MAX_EVENTS_PER_SECOND = 200  # a flood of ARP must not become a flood of lines
CACHE_LIMIT = 8192

# Classic BPF opcodes (linux/filter.h).
LD_H_ABS, LD_B_ABS, LD_H_IND, LDX_MSH = 0x28, 0x30, 0x48, 0xB1
JEQ, JSET, RET_K = 0x15, 0x45, 0x06
ACCEPT_BYTES = 262144  # snap length; the whole frame


# Instruction indexes the program jumps to.
_REJECT, _ACCEPT = 14, 15


def bpf_program() -> list[tuple[int, int, int, int]]:
    """ARP, or IPv4 UDP with port 67 or 68 on either side, as (code, jt, jf, k).

    Offsets assume an Ethernet header of 14 bytes with no VLAN tag. A fragment
    other than the first is rejected: it has no UDP header to read."""
    # (code, k, if true go to, if false go to); None = the next instruction.
    table = [
        (LD_H_ABS, 12, None, None),          # 0  ethertype
        (JEQ, 0x0806, _ACCEPT, None),        # 1  ARP: accept
        (JEQ, 0x0800, None, _REJECT),        # 2  anything but IPv4: reject
        (LD_B_ABS, 23, None, None),          # 3  IP protocol
        (JEQ, 17, None, _REJECT),            # 4  anything but UDP: reject
        (LD_H_ABS, 20, None, None),          # 5  flags and fragment offset
        (JSET, 0x1FFF, _REJECT, None),       # 6  a later fragment: reject
        (LDX_MSH, 14, None, None),           # 7  X = IP header length
        (LD_H_IND, 14, None, None),          # 8  source port
        (JEQ, 67, _ACCEPT, None),            # 9
        (JEQ, 68, _ACCEPT, None),            # 10
        (LD_H_IND, 16, None, None),          # 11 destination port
        (JEQ, 67, _ACCEPT, None),            # 12
        (JEQ, 68, _ACCEPT, None),            # 13 neither: falls into the reject below
        (RET_K, 0, None, None),              # 14 reject
        (RET_K, ACCEPT_BYTES, None, None),   # 15 accept
    ]
    program = []
    for pc, (code, k, if_true, if_false) in enumerate(table):
        # Jump offsets count from the instruction after this one.
        jt = 0 if if_true is None else if_true - pc - 1
        jf = 0 if if_false is None else if_false - pc - 1
        program.append((code, jt, jf, k))
    return program


def attach_filter(sock: socket.socket) -> None:
    program = bpf_program()
    raw = b"".join(struct.pack("HBBI", code, jt, jf, k) for code, jt, jf, k in program)
    buffer = ctypes.create_string_buffer(raw, len(raw))
    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    fprog = struct.pack("@HP", len(program), ctypes.addressof(buffer))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def events_from(pkt: dict) -> list[dict]:
    """The watcher's events in a decoded frame (none for anything else)."""
    out = []
    arp = pkt.get("arp")
    if arp:
        out.append({"t": "arp", "ip": arp["spa"], "mac": arp["sha"], "op": arp["op"], "eth": pkt.get("src_mac")})
    dhcp = pkt.get("dhcp")
    if dhcp:
        out.append({"t": "dhcp", **dhcp, "src": pkt.get("src"), "eth": pkt.get("src_mac")})
    return out


def run(config: dict) -> None:
    iface = config.get("iface") or ""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        attach_filter(sock)  # before the bind, so no unfiltered frame is ever queued
        if iface:
            sock.bind((iface, 0))
    except OSError:
        sock.close()
        raise
    sock.settimeout(1.0)

    last_sent: dict[tuple, float] = {}
    window_start, window_count = time.monotonic(), 0
    next_beat = time.monotonic() + BEAT_SECONDS
    reported = False
    reason = "finished"
    try:
        while True:
            mono = time.monotonic()
            if mono >= next_beat:
                emit({"t": "beat", "ts": time.time()})
                next_beat = mono + BEAT_SECONDS
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as error:
                reason = f"socket error: {error}"
                break
            try:
                pkt = capture_worker.decode_frame(frame, addr[3])
                events = events_from(pkt) if pkt else []
            except Exception:  # noqa: BLE001 - network input: one bad frame costs one frame
                if not reported:
                    reported = True
                    traceback.print_exc()
                continue
            for event in events:
                key = (event["t"], event.get("ip") or event.get("server"), event.get("mac") or event.get("client"),
                       event.get("op") or event.get("type"))
                if mono - last_sent.get(key, -REPEAT_SECONDS) < REPEAT_SECONDS:
                    continue
                if mono - window_start >= 1:
                    window_start, window_count = mono, 0
                if window_count >= MAX_EVENTS_PER_SECOND:
                    continue
                window_count += 1
                if len(last_sent) >= CACHE_LIMIT:
                    last_sent.clear()
                last_sent[key] = mono
                emit(event)
    except KeyboardInterrupt:
        reason = "stopped"
    finally:
        sock.close()
        emit({"t": "end", "reason": reason, "ts": time.time()})


if __name__ == "__main__":
    try:
        run(json.loads(os.environ.get("NETWATCH_CONFIG", "{}")))
    except PermissionError:
        emit({"t": "end", "reason": "the helper isn't allowed a raw socket (needs NET_RAW)", "ts": time.time()})
        sys.exit(1)
    except OSError as error:
        emit({"t": "end", "reason": f"couldn't start the watcher: {error}", "ts": time.time()})
        sys.exit(1)
