"""The packet sniffer itself. Runs inside a throwaway helper container on the
host's network (see capture.py), never in the agent: the agent sits behind
Docker's bridge and would only see its own traffic.

Reads an AF_PACKET socket (no tcpdump, no libpcap — the helper image is the
agent's own), decodes Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP / DNS
by hand, and prints JSON lines on stdout for the agent to read:

  {"t": "pkt", ...}   one decoded packet (capped per second, see MAX_PPS)
  {"t": "tick", ...}  once a second: exact totals and the busiest flows
  {"t": "end", ...}   last line, with why it stopped

Totals and flows count *every* matching packet; only the packet list is
sampled. By default only headers are kept — the bytes after the transport
header are cut off, so a capture does not hold what people were reading.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
MAX_PPS = 120  # packets per second sent to the list; totals stay exact
MAX_FLOWS = 150  # flows per tick line
PAYLOAD_BYTES = 64  # kept after the headers when payload is switched on

PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
TCP_FLAGS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10), ("U", 0x20))
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
ICMP_TYPES = {0: "echo reply", 3: "unreachable", 5: "redirect", 8: "echo request", 11: "time exceeded"}
# Well-known ports worth naming in the list.
SERVICES = {
    22: "ssh", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 123: "ntp", 137: "netbios", 138: "netbios",
    443: "https", 445: "smb", 1900: "ssdp", 3000: "http", 5353: "mdns", 8080: "http", 8096: "jellyfin",
    8123: "agent", 32400: "plex", 41641: "tailscale",
}

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


def decode_l4(proto: int, data: bytes, v6: bool = False) -> dict:
    """Ports, flags and a one-line summary for the transport layer; ``hdr``
    is how many bytes of ``data`` are header (the rest is payload)."""
    out = {"hdr": 0}
    if proto == 6 and len(data) >= 20:
        sport, dport, seq, ack, off, flags, win = struct.unpack("!HHIIBBH", data[:16])
        hdr = (off >> 4) * 4
        names = "".join(n for n, bit in TCP_FLAGS if flags & bit) or "."
        out.update(sport=sport, dport=dport, hdr=min(hdr, len(data)), flags=names, win=win, seq=seq, ack=ack)
        out["info"] = f"{sport} → {dport} [{names}] win {win}"
    elif proto == 17 and len(data) >= 8:
        sport, dport, length = struct.unpack("!HHH", data[:6])
        out.update(sport=sport, dport=dport, hdr=8)
        out["info"] = f"{sport} → {dport} len {max(0, length - 8)}"
        if 53 in (sport, dport) or 5353 in (sport, dport):
            dns = decode_dns(data[8:])
            if dns:
                out["info"], out["app"] = dns, "dns" if 53 in (sport, dport) else "mdns"
    elif proto in (1, 58) and len(data) >= 4:
        kind, code = data[0], data[1]
        if proto == 58:
            label = {128: "echo request", 129: "echo reply", 133: "router solicit", 134: "router advert", 135: "neighbour solicit", 136: "neighbour advert"}.get(kind, f"type {kind}")
        else:
            label = ICMP_TYPES.get(kind, f"type {kind}")
        out.update(hdr=min(8, len(data)), info=label if code == 0 else f"{label} (code {code})")
    return out


def decode_ip(data: bytes, hatype_note: str = "") -> dict | None:
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
        l4 = decode_l4(proto, data[ihl:])
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
        l4 = decode_l4(proto, data[pos:], v6=True)
        out.update(l4)
        out["proto"] = PROTOS.get(proto, f"proto {proto}")
        out["hdr"] = pos + l4["hdr"]
        out.setdefault("info", "")
        return out
    return None


def decode_frame(frame: bytes, hatype: int) -> dict | None:
    """One captured frame → a flat dict, or None for something unreadable."""
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
    if ethertype == 0x0806 and len(frame) >= pos + 28:
        op = struct.unpack("!H", frame[pos + 6:pos + 8])[0]
        sha, spa = mac(frame[pos + 8:pos + 14]), socket.inet_ntoa(frame[pos + 14:pos + 18])
        tpa = socket.inet_ntoa(frame[pos + 24:pos + 28])
        info = f"who has {tpa}? tell {spa}" if op == 1 else f"{spa} is at {sha}"
        return {"proto": "ARP", "src": spa, "dst": tpa, "src_mac": src_mac, "dst_mac": dst_mac, "info": info, "hdr": pos + 28, "l2": pos}
    if ethertype == 0x88CC:
        return {"proto": "LLDP", "src": src_mac, "dst": dst_mac, "src_mac": src_mac, "dst_mac": dst_mac, "info": "", "hdr": pos, "l2": pos}
    return {"proto": f"eth {ethertype:#06x}", "src": src_mac, "dst": dst_mac, "src_mac": src_mac, "dst_mac": dst_mac, "info": "", "hdr": pos, "l2": pos}


def matches(pkt: dict, flt: dict) -> bool:
    """The filter the agent validated: any of ``host``, ``port``, ``proto``."""
    host = flt.get("host")
    if host and host not in (pkt.get("src"), pkt.get("dst")):
        return False
    port = flt.get("port")
    if port and port not in (pkt.get("sport"), pkt.get("dport")):
        return False
    proto = flt.get("proto")
    if proto:
        if proto == "dns":
            return pkt.get("app") == "dns"
        if proto != pkt.get("proto", "").lower():
            return False
    return True


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


def run(config: dict) -> None:
    iface = config.get("iface") or ""
    duration = max(1, min(int(config.get("duration", 60)), 600))
    flt = config.get("filter") or {}
    keep_payload = bool(config.get("payload"))
    deadline = time.time() + duration

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface and iface != "any":
        sock.bind((iface, 0))
    sock.settimeout(0.25)
    # Big enough that a burst between two reads isn't dropped by the kernel.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass

    totals = {"pkts": 0, "bytes": 0}
    protos: dict[str, list[int]] = {}
    flows: dict[tuple, list] = {}
    sent_this_second, second_start, tick_at = 0, time.time(), time.time() + 1
    skipped_list = 0
    reason = "finished"

    try:
        while True:
            now = time.time()
            if now >= deadline:
                break
            if now >= tick_at:
                top = sorted(flows.items(), key=lambda kv: kv[1][1], reverse=True)[:MAX_FLOWS]
                emit({
                    "t": "tick", "ts": now, "pkts": totals["pkts"], "bytes": totals["bytes"],
                    "protos": protos, "skipped": skipped_list,
                    "flows": [[*k, v[0], v[1], v[2], v[3]] for k, v in top],
                })
                totals, protos, flows = {"pkts": 0, "bytes": 0}, {}, {}
                skipped_list = 0
                tick_at = now + 1
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as error:
                reason = f"socket error: {error}"
                break
            ifname, _, pkttype, hatype = addr[0], addr[1], addr[2], addr[3]
            pkt = decode_frame(frame, hatype)
            if pkt is None or not matches(pkt, flt):
                continue
            size = len(frame)
            totals["pkts"] += 1
            totals["bytes"] += size
            row = protos.setdefault(pkt["proto"], [0, 0])
            row[0] += 1
            row[1] += size
            key = flow_key(pkt)
            flow = flows.setdefault(key, [0, 0, 0, 0])  # pkts, bytes, out pkts, in pkts
            flow[0] += 1
            flow[1] += size
            flow[2 if pkttype == 4 else 3] += 1

            if now - second_start >= 1:
                second_start, sent_this_second = now, 0
            if sent_this_second >= MAX_PPS:
                skipped_list += 1
                continue
            sent_this_second += 1
            keep = pkt.get("hdr", 0) + (PAYLOAD_BYTES if keep_payload else 0)
            pkt.update(
                t="pkt", ts=now, len=size, iface=ifname,
                dir="out" if pkttype == 4 else "in",
                svc=service(pkt), hex=frame[:keep].hex(),
            )
            pkt.pop("hdr", None)
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
