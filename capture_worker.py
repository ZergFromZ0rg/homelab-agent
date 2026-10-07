"""The packet sniffer itself. Runs inside a throwaway helper container on the
host's network (see capture.py), never in the agent: the agent sits behind
Docker's bridge and would only see its own traffic.

Reads an AF_PACKET socket (no tcpdump, no libpcap — the helper image is the
agent's own), decodes Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP / DNS
DHCP / NTP / plain HTTP by hand, and prints JSON lines on stdout for the agent to read:

  {"t": "pkt", ...}   one decoded packet (capped per second, see MAX_PPS)
  {"t": "tick", ...}  once a second: exact totals and the busiest flows
  {"t": "end", ...}   last line, with why it stopped

Totals and flows count *every* matching packet; only the packet list is
sampled. By default only headers are kept — the bytes after the transport
header are cut off, so a capture does not hold what people were reading.
``payload`` can be raised to the first 64 bytes, or to whole packets (what
"Follow stream" needs). Things read out of the payload and kept regardless —
a TLS server name, a DNS name, an HTTP request line without its query string
and its Host header, a DHCP host name — are the only exceptions.

Kernel side: the socket asks the kernel for packet timestamps (not the time
Python got round to reading it), reports the kernel's own drop counter once a
second, and can put the interface in promiscuous mode.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time
import traceback

import capture_filter

ETH_P_ALL = 0x0003
MAX_PPS = 120  # packets per second sent to the list; totals stay exact
MAX_PPS_FULL = 600  # with whole packets kept: a stream needs most of its segments
MAX_FLOWS = 150  # flows per tick line
PAYLOAD_BYTES = {"none": 0, "64": 64, "full": 1600}  # kept after the headers

# linux/if_packet.h, which the socket module doesn't export.
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_STATISTICS = 6
PACKET_MR_PROMISC = 1
SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)

PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
TCP_FLAGS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10), ("U", 0x20))
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
NTP_MODES = {1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server", 5: "broadcast"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
ISSUE_LABELS = {
    "retransmit": "TCP retransmission", "gap": "gap: lost or reordered", "dup-ack": "duplicate ACK",
    "zero-window": "zero window", "reset": "connection reset",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
ICMP_TYPES = {0: "echo reply", 3: "unreachable", 5: "redirect", 8: "echo request", 11: "time exceeded"}
# Well-known ports worth naming in the list.
SERVICES = {
    22: "ssh", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 123: "ntp", 137: "netbios", 138: "netbios",
    443: "https", 445: "smb", 1900: "ssdp", 3000: "http", 5353: "mdns", 8080: "http", 8096: "jellyfin",
    8123: "agent", 32400: "plex", 41641: "tailscale",
}

# sockaddr_ll.sll_pkttype: sent by this host, or (promiscuous) meant for someone else.
PACKET_TYPES = {4: "out", 3: "other"}

# hatype values from linux/if_arp.h whose frames carry no Ethernet header.
RAW_IP_TYPES = {65534, 519, 768, 769}  # none (tun), ipv6-over-nothing, ipip, ip6tnl


def mac(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def dns_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """The name at ``pos`` and the offset just past it in the *record*."""
    labels, jumped, end = [], False, pos
    while depth < 20:
        if pos >= len(data):
            raise ValueError("truncated")
        length = data[pos]
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped, pos, depth = True, pointer, depth + 1
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
        if not jumped:
            end = pos
    return ".".join(labels), end


def decode_dns(data: bytes) -> str | None:
    """"A example.com?" for a query, "A example.com → 1.2.3.4" for an answer."""
    if len(data) < 12:
        return None
    ident, flags, qd, an = struct.unpack("!HHHH", data[:8])
    try:
        if qd < 1:
            return None
        name, pos = dns_name(data, 12)
        qtype = struct.unpack("!H", data[pos:pos + 2])[0]
        kind = DNS_TYPES.get(qtype, str(qtype))
        if not flags & 0x8000:
            return f"{kind} {name}?"
        rcode = flags & 0xF
        if rcode:
            return f"{kind} {name} → {('NXDOMAIN' if rcode == 3 else 'rcode %d' % rcode)}"
        answers, pos = [], pos + 4
        for _ in range(min(an, 4)):
            _, pos = dns_name(data, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            rdata = data[pos + 10:pos + 10 + rdlen]
            pos += 10 + rdlen
            if rtype == 1 and rdlen == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (5, 12):
                answers.append(dns_name(data, pos - rdlen)[0])
        return f"{kind} {name} → {', '.join(answers) if answers else 'no answer'}"
    except (ValueError, struct.error, IndexError):
        return f"{ident:#06x} (truncated)"


def tls_server_name(data: bytes) -> str | None:
    """The server name a TLS ClientHello asks for (the SNI extension), or None
    when this isn't a ClientHello or has no name. Reads only that field."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 43  # record header (5) + handshake header (4) + version (2) + random (32)
        pos += 1 + data[pos]  # session id
        pos += 2 + struct.unpack("!H", data[pos:pos + 2])[0]  # cipher suites
        pos += 1 + data[pos]  # compression methods
        end = min(len(data), pos + 2 + struct.unpack("!H", data[pos:pos + 2])[0])
        pos += 2
        while pos + 4 <= end:
            kind, length = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if kind == 0 and length >= 5:  # server_name: list length, type (0 = host name), name length, name
                size = struct.unpack("!H", data[pos + 3:pos + 5])[0]
                name = data[pos + 5:pos + 5 + size]
                if data[pos + 2] == 0 and name and len(name) == size:
                    return name.decode("ascii", "replace")
                return None
            pos += length
    except (IndexError, struct.error):
        return None
    return None


def decode_dhcp(data: bytes) -> dict | None:
    """"DHCP Offer 192.168.1.50 “iphone”" — the message type, the address
    offered or asked for, and the client's host name."""
    if len(data) < 241 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    yiaddr = socket.inet_ntoa(data[16:20])
    client = mac(data[28:34])
    options, pos = {}, 240
    while pos < len(data):
        code = data[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        size = data[pos + 1]
        options[code] = data[pos + 2:pos + 2 + size]
        pos += 2 + size
    kind = DHCP_TYPES.get(options.get(53, b"\0")[0] if options.get(53) else 0, "message")
    host = options[12].decode("ascii", "replace")[:63] if options.get(12) else None
    wanted = socket.inet_ntoa(options[50]) if len(options.get(50, b"")) == 4 else None
    parts = [f"DHCP {kind}"]
    if kind in ("Offer", "ACK") and yiaddr != "0.0.0.0":
        parts.append(yiaddr)
    elif wanted:
        parts.append(f"wants {wanted}")
    if host:
        parts.append(f"\u201c{host}\u201d")
    if kind not in ("Offer", "ACK", "NAK"):
        parts.append(f"({client})")
    out = {"app": "dhcp", "info": " ".join(parts)}
    if host:
        out["name"] = host
    return out


def decode_ntp(data: bytes) -> dict | None:
    if len(data) < 48:
        return None
    version, mode = (data[0] >> 3) & 7, data[0] & 7
    if version not in (1, 2, 3, 4) or mode not in NTP_MODES:
        return None
    info = f"NTP v{version} {NTP_MODES[mode]}"
    if mode in (4, 5):
        info += f" stratum {data[1]}"
    return {"app": "ntp", "info": info}


def decode_http(payload: bytes) -> dict | None:
    """A plain-HTTP request line (query string cut off — it is where tokens
    live) with its Host header, or a response status line."""
    head = payload[:1500]
    if head.startswith(b"HTTP/1."):
        parts = head.split(b"\r\n", 1)[0][:100].decode("latin-1").split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return {"app": "http", "info": f"HTTP {parts[1]} {parts[2] if len(parts) > 2 else ''}".strip()}
        return None
    if not head.startswith(HTTP_METHODS):
        return None
    line, _, rest = head.partition(b"\r\n")
    pieces = line.decode("latin-1").split(" ")
    if len(pieces) < 3 or not pieces[2].startswith("HTTP/"):
        return None
    target, cut, _ = pieces[1].partition("?")
    target = target[:120] + ("?\u2026" if cut else "")
    host = None
    for header in rest.split(b"\r\n"):
        if not header:
            break
        if header[:5].lower() == b"host:":
            host = header[5:].strip().decode("latin-1")[:253] or None
            break
    out = {"app": "http", "info": f"{pieces[0]} {target}" + (f"  Host: {host}" if host else "")}
    if host:
        out["name"] = host
    return out


class TcpHealth:
    """Per-direction sequence tracking, to flag what Wireshark's expert info
    would: retransmissions, gaps, duplicate ACKs, zero windows and resets.
    Seen on every TCP packet before any filter, so a narrow filter doesn't
    blind it. Bounded: a flood of flows resets the table."""

    MAX = 50_000

    def __init__(self) -> None:
        self.state: dict[tuple, dict] = {}

    @staticmethod
    def _signed(diff: int) -> int:
        return ((diff + 2**31) % 2**32) - 2**31

    def check(self, pkt: dict) -> list[str]:
        if pkt.get("proto") != "TCP" or "seq" not in pkt:
            return []
        key = (pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"])
        st = self.state.get(key)
        if st is None:
            if len(self.state) >= self.MAX:
                self.state.clear()
            st = self.state[key] = {"next": None, "ack": None, "dups": 0}
        flags, plen, seq = pkt.get("flags", ""), pkt.get("plen", 0), pkt["seq"]
        syn, fin, rst = "S" in flags, "F" in flags, "R" in flags
        issues: list[str] = []
        if rst:
            issues.append("reset")
        elif pkt.get("win") == 0 and not syn:
            issues.append("zero-window")
        span = plen + (1 if syn else 0) + (1 if fin else 0)
        if span and not rst:
            end = (seq + span) & 0xFFFFFFFF
            if st["next"] is None:
                st["next"] = end
            else:
                behind = self._signed(seq - st["next"])
                if behind < 0:
                    if not (plen <= 1 and not syn and not fin and behind == -1):  # keep-alive probe
                        issues.append("retransmit")
                    if self._signed(end - st["next"]) > 0:
                        st["next"] = end
                else:
                    if behind > 0:
                        issues.append("gap")
                    st["next"] = end
        if "A" in flags and not (span or rst):
            marker = (pkt.get("ack"), pkt.get("win"))
            if st["ack"] == marker:
                st["dups"] += 1
                if st["dups"] >= 2:
                    issues.append("dup-ack")
            else:
                st["ack"], st["dups"] = marker, 0
        return issues


def decode_l4(proto: int, data: bytes) -> dict:
    """Ports, flags and a one-line summary for the transport layer; ``hdr``
    is how many bytes of ``data`` are header (the rest is payload)."""
    out = {"hdr": 0}
    if proto == 6 and len(data) >= 20:
        sport, dport, seq, ack, off, flags, win = struct.unpack("!HHIIBBH", data[:16])
        hdr = (off >> 4) * 4
        names = "".join(n for n, bit in TCP_FLAGS if flags & bit) or "."
        out.update(sport=sport, dport=dport, hdr=min(hdr, len(data)), flags=names, win=win, seq=seq, ack=ack)
        out["info"] = f"{sport} → {dport} [{names}] win {win}"
        payload = data[hdr:]
        out["plen"] = len(payload)
        if payload:
            name = tls_server_name(payload)
            if name:
                out.update(sni=name, app="tls", info=f"Client Hello → {name}")
            else:
                http = decode_http(payload)
                if http:
                    out.update(http)
    elif proto == 17 and len(data) >= 8:
        sport, dport, length = struct.unpack("!HHH", data[:6])
        out.update(sport=sport, dport=dport, hdr=8)
        out["info"] = f"{sport} → {dport} len {max(0, length - 8)}"
        if 53 in (sport, dport) or 5353 in (sport, dport):
            dns = decode_dns(data[8:])
            if dns:
                out["info"], out["app"] = dns, "dns" if 53 in (sport, dport) else "mdns"
        elif sport in (67, 68) and dport in (67, 68):  # client↔server, or relay↔server (67↔67)
            out.update(decode_dhcp(data[8:]) or {})
        elif 123 in (sport, dport):
            out.update(decode_ntp(data[8:]) or {})
    elif proto in (1, 58) and len(data) >= 4:
        kind, code = data[0], data[1]
        if proto == 58:
            label = {128: "echo request", 129: "echo reply", 133: "router solicit", 134: "router advert", 135: "neighbour solicit", 136: "neighbour advert"}.get(kind, f"type {kind}")
        else:
            label = ICMP_TYPES.get(kind, f"type {kind}")
        out.update(hdr=min(8, len(data)), info=label if code == 0 else f"{label} (code {code})")
    return out


def decode_ip(data: bytes) -> dict | None:
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        ihl = (data[0] & 0xF) * 4
        ttl, proto = data[8], data[9]
        total = struct.unpack("!H", data[2:4])[0]
        frag = struct.unpack("!H", data[6:8])[0]
        src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
        out = {"src": src, "dst": dst, "ttl": ttl, "ip": 4, "ip_len": total}
        if frag & 0x1FFF:  # a later fragment has no transport header
            out.update(proto="IPv4 frag", hdr=ihl, info="fragment")
            return out
        end = total if ihl <= total <= len(data) else len(data)
        l4 = decode_l4(proto, data[ihl:end])
        out.update(l4)
        out["proto"] = PROTOS.get(proto, f"proto {proto}")
        out["hdr"] = ihl + l4["hdr"]
        out.setdefault("info", "")
        return out
    if version == 6 and len(data) >= 40:
        proto, hop = data[6], data[7]
        plen = struct.unpack("!H", data[4:6])[0]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        pos = 40
        # Skip hop-by-hop / routing / destination-options extension headers.
        while proto in (0, 43, 60) and pos + 8 <= len(data):
            proto, ext = data[pos], (data[pos + 1] + 1) * 8
            pos += ext
        out = {"src": src, "dst": dst, "ttl": hop, "ip": 6, "ip_len": plen + 40}
        end = 40 + plen if 40 + plen <= len(data) and plen else len(data)
        l4 = decode_l4(proto, data[pos:end])
        out.update(l4)
        out["proto"] = PROTOS.get(proto, f"proto {proto}")
        out["hdr"] = pos + l4["hdr"]
        out.setdefault("info", "")
        return out
    return None


def decode_frame(frame: bytes, hatype: int) -> dict | None:
    """One captured frame → a flat dict, or None for something unreadable."""
    pkt = _decode_frame(frame, hatype)
    if pkt is not None:
        pkt["len"] = len(frame)  # before filtering: ``len > N`` needs it
    return pkt


def _decode_frame(frame: bytes, hatype: int) -> dict | None:
    if hatype in RAW_IP_TYPES:
        out = decode_ip(frame)
        if out:
            out["l2"] = 0
        return out
    if len(frame) < 14:
        return None
    dst_mac, src_mac = mac(frame[0:6]), mac(frame[6:12])
    ethertype, pos = struct.unpack("!H", frame[12:14])[0], 14
    while ethertype in (0x8100, 0x88A8) and len(frame) >= pos + 4:  # VLAN tags
        ethertype = struct.unpack("!H", frame[pos + 2:pos + 4])[0]
        pos += 4
    if ethertype in (0x0800, 0x86DD):
        out = decode_ip(frame[pos:])
        if out is None:
            return None
        out.update(src_mac=src_mac, dst_mac=dst_mac, l2=pos)
        out["hdr"] += pos
        return out
    # Ethernet/IPv4 ARP only: another hardware or protocol type has other field sizes.
    if ethertype == 0x0806 and len(frame) >= pos + 28 and frame[pos:pos + 6] == b"\x00\x01\x08\x00\x06\x04":
        op = struct.unpack("!H", frame[pos + 6:pos + 8])[0]
        sha, spa = mac(frame[pos + 8:pos + 14]), socket.inet_ntoa(frame[pos + 14:pos + 18])
        tpa = socket.inet_ntoa(frame[pos + 24:pos + 28])
        info = f"who has {tpa}? tell {spa}" if op == 1 else f"{spa} is at {sha}"
        return {"proto": "ARP", "src": spa, "dst": tpa, "src_mac": src_mac, "dst_mac": dst_mac, "info": info, "hdr": pos + 28, "l2": pos}
    if ethertype == 0x88CC:
        return {"proto": "LLDP", "src": src_mac, "dst": dst_mac, "src_mac": src_mac, "dst_mac": dst_mac, "info": "", "hdr": pos, "l2": pos}
    return {"proto": f"eth {ethertype:#06x}", "src": src_mac, "dst": dst_mac, "src_mac": src_mac, "dst_mac": dst_mac, "info": "", "hdr": pos, "l2": pos}


def service(pkt: dict) -> str | None:
    for port in (pkt.get("dport"), pkt.get("sport")):
        if port in SERVICES:
            return SERVICES[port]
    return pkt.get("app")


def flow_key(pkt: dict) -> tuple:
    """Both directions of a conversation share a key."""
    a = (pkt.get("src"), pkt.get("sport") or 0)
    b = (pkt.get("dst"), pkt.get("dport") or 0)
    lo, hi = sorted((a, b), key=lambda e: (str(e[0]), e[1]))
    return (pkt.get("proto"), lo[0], lo[1], hi[0], hi[1])


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def kernel_drops(sock: socket.socket) -> int:
    """Packets the kernel had to throw away since the last call (reading the
    counter resets it). 0 where the platform won't say."""
    try:
        return struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))[1]
    except (OSError, struct.error):
        return 0


def open_socket(iface: str, promisc: bool) -> tuple[socket.socket, bool]:
    """The raw socket, bound and tuned; and whether kernel timestamps are on."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface and iface != "any":
        sock.bind((iface, 0))
        if promisc:
            # Dropped by the kernel when the socket closes, so it can't be left on.
            try:
                mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b"")
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            except OSError as error:
                sock.close()
                raise OSError(f"couldn't enter promiscuous mode on {iface}: {error}") from error
    sock.settimeout(0.25)
    # Big enough that a burst between two reads isn't dropped by the kernel.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        stamped = True
    except OSError:
        stamped = False
    return sock, stamped


def read_packet(sock: socket.socket, stamped: bool) -> tuple[bytes, tuple, float | None]:
    """(frame, address, kernel timestamp or None)."""
    frame, ancillary, _flags, addr = sock.recvmsg(65535, socket.CMSG_SPACE(16) if stamped else 0)
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS and len(data) >= 16:
            seconds, nanos = struct.unpack("qq", data[:16])
            return frame, addr, seconds + nanos / 1e9
    return frame, addr, None


def run(config: dict) -> None:
    iface = config.get("iface") or ""
    duration = max(1, min(int(config.get("duration", 60)), 600))
    combined = capture_filter.combine(config.get("filter") or {})
    expression = capture_filter.compile_filter(combined) if combined else None
    payload_mode = config.get("payload") if config.get("payload") in PAYLOAD_BYTES else "none"
    max_pps = MAX_PPS_FULL if payload_mode == "full" else MAX_PPS
    # Monotonic for every deadline and interval: a clock step (NTP, a resume)
    # must not cut a capture short or stretch it. Wall time is only for stamps.
    deadline = time.monotonic() + duration

    sock, stamped = open_socket(iface, bool(config.get("promisc")))
    health = TcpHealth()

    totals = {"pkts": 0, "bytes": 0}
    protos: dict[str, list[int]] = {}
    flows: dict[tuple, list] = {}
    issue_counts: dict[str, int] = {}
    sent_this_second, second_start, tick_at = 0, time.monotonic(), time.monotonic() + 1
    skipped_list = 0
    reported_error = False
    reason = "finished"

    try:
        while True:
            mono = time.monotonic()
            if mono >= deadline:
                break
            if mono >= tick_at:
                top = sorted(flows.items(), key=lambda kv: kv[1][1], reverse=True)[:MAX_FLOWS]
                emit({
                    "t": "tick", "ts": time.time(), "pkts": totals["pkts"], "bytes": totals["bytes"],
                    "protos": protos, "skipped": skipped_list, "drops": kernel_drops(sock),
                    "issues": issue_counts,
                    "flows": [[*k, *v] for k, v in top],
                })
                totals, protos, flows, issue_counts = {"pkts": 0, "bytes": 0}, {}, {}, {}
                skipped_list = 0
                tick_at = mono + 1
            try:
                frame, addr, stamp = read_packet(sock, stamped)
            except socket.timeout:
                continue
            except OSError as error:
                reason = f"socket error: {error}"
                break
            ifname, _, pkttype, hatype = addr[0], addr[1], addr[2], addr[3]
            # Every byte here came off the network, so a packet nobody
            # anticipated must cost one packet, not the whole capture.
            try:
                pkt = decode_frame(frame, hatype)
                if pkt is None:
                    continue
                issues = health.check(pkt)  # before the filter: it needs both directions
                if expression and not expression(pkt):
                    continue
            except Exception:  # noqa: BLE001 - see above
                if not reported_error:
                    reported_error = True
                    traceback.print_exc()  # once, to stderr; the agent keeps the last lines
                continue
            if issues:
                pkt["issues"] = issues
                pkt["info"] += "  [" + ", ".join(ISSUE_LABELS[i] for i in issues) + "]"
            size = len(frame)
            totals["pkts"] += 1
            totals["bytes"] += size
            row = protos.setdefault(pkt["proto"], [0, 0])
            row[0] += 1
            row[1] += size
            key = flow_key(pkt)
            # pkts, bytes, out pkts, in pkts, server/host name, issue counts
            flow = flows.setdefault(key, [0, 0, 0, 0, None, {}])
            name = pkt.get("sni") or pkt.get("name")
            if name:
                flow[4] = name
            flow[0] += 1
            flow[1] += size
            flow[2 if pkttype == 4 else 3] += 1
            for issue in issues:
                flow[5][issue] = flow[5].get(issue, 0) + 1
                issue_counts[issue] = issue_counts.get(issue, 0) + 1

            if mono - second_start >= 1:
                second_start, sent_this_second = mono, 0
            if sent_this_second >= max_pps:
                skipped_list += 1
                continue
            sent_this_second += 1
            offset = pkt.pop("hdr", 0)
            pkt.update(
                t="pkt", ts=stamp or time.time(), len=size, iface=ifname,
                dir=PACKET_TYPES.get(pkttype, "in"),
                svc=service(pkt), poff=offset, flow="|".join(str(part) for part in key),
                hex=frame[:offset + PAYLOAD_BYTES[payload_mode]].hex(),
            )
            emit(pkt)
    except KeyboardInterrupt:
        reason = "stopped"
    finally:
        sock.close()
        emit({"t": "end", "reason": reason, "ts": time.time()})


if __name__ == "__main__":
    try:
        run(json.loads(os.environ.get("CAPTURE_CONFIG", "{}")))
    except PermissionError:
        emit({"t": "end", "reason": "the helper isn't allowed a raw socket (needs NET_RAW)", "ts": time.time()})
        sys.exit(1)
    except OSError as error:
        emit({"t": "end", "reason": f"couldn't open the capture: {error}", "ts": time.time()})
        sys.exit(1)
