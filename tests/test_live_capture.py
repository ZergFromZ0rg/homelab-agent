"""The sniffers against a real kernel.

Everything else about capturing is tested with fake sockets, which cannot catch
the things that only a real ``AF_PACKET`` socket does: a BPF program the kernel
rejects or interprets differently from a hand-written interpreter, kernel
timestamps arriving in ancillary data, the drop counter, promiscuous mode,
real TCP flags. These tests send real packets over the loopback interface and
read them back through the real sniffers.

They need Linux and permission to open a raw packet socket (root, or
CAP_NET_RAW), and are skipped otherwise — which is every developer laptop.
They run fine inside the agent's own image, which has the same Python and no
other dependency:

    docker run --rm --cap-add NET_RAW -v "$PWD":/src -w /src homelab-agent \\
        sh -c "pip install -q pytest && python -m pytest tests/test_live_capture.py -v"

(The container's own ``lo`` is used, so the host's network is untouched.)
"""

from __future__ import annotations

import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOOPBACK = "lo"


def _can_sniff() -> bool:
    if sys.platform != "linux":
        return False
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except (PermissionError, OSError, AttributeError):
        return False
    probe.close()
    return os.path.exists(f"/sys/class/net/{LOOPBACK}")


pytestmark = pytest.mark.skipif(not _can_sniff(), reason="needs Linux and a raw packet socket (root or CAP_NET_RAW)")


# --- helpers -------------------------------------------------------------------------------

def run_sniffer(script: str, env_name: str, config: dict, traffic, lead: float = 0.6) -> list[dict]:
    """Run a sniffer helper as the agent would (a separate process, its config
    in the environment), send ``traffic()`` once it is listening, and return the
    JSON lines it printed."""
    process = subprocess.Popen(
        [sys.executable, str(ROOT / script)],
        cwd=ROOT, env={**os.environ, env_name: json.dumps(config)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(lead)  # let it open its socket before anything is sent
    traffic()
    try:
        out, err = process.communicate(timeout=config.get("duration", 3) + 15)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
    lines = [json.loads(line) for line in out.splitlines() if line.strip().startswith("{")]
    assert lines, f"the sniffer printed nothing; stderr: {err[-500:]}"
    return lines


def dns_query(name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def udp_to(port: int, payload: bytes) -> None:
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(payload, ("127.0.0.1", port))  # nobody need be listening: the packet crosses lo regardless
    finally:
        sender.close()


def http_exchange(request: bytes) -> None:
    """A real TCP connection to a listener of ours: SYN, SYN-ACK, ACK, data, FIN."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname())
    peer, _ = server.accept()
    client.sendall(request)
    peer.recv(4096)
    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    client.recv(4096)
    for sock in (client, peer, server):
        sock.close()


def arp_frame(sender_mac: bytes, sender_ip: str, target_ip: str) -> bytes:
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, sender_mac, socket.inet_aton(sender_ip), bytes(6), socket.inet_aton(target_ip))
    return bytes(6) + sender_mac + struct.pack("!H", 0x0806) + body


def inject(frame: bytes) -> None:
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sender.bind((LOOPBACK, 0))
        sender.send(frame)
    finally:
        sender.close()


def udp_from(source_port: int, to_port: int, payload: bytes) -> None:
    """A datagram from a *specific* source port, as real DHCP (67 <-> 68) always
    is. Binding a low port needs root or NET_BIND_SERVICE; without it the test
    that needs this is skipped rather than failed."""
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            sender.bind(("127.0.0.1", source_port))
        except PermissionError:
            pytest.skip("binding a port below 1024 needs root or NET_BIND_SERVICE")
        sender.sendto(payload, ("127.0.0.1", to_port))
    finally:
        sender.close()


def dhcp_offer() -> bytes:
    head = struct.pack("!BBBBIHH4s4s4s4s", 2, 1, 6, 0, 0xBEEF, 0, 0, bytes(4), socket.inet_aton("192.168.77.50"), bytes(4), bytes(4))
    head += bytes.fromhex("aabbcc000009") + bytes(10) + bytes(64) + bytes(128) + b"\x63\x82\x53\x63"
    return head + bytes([53, 1, 2, 54, 4, 192, 168, 77, 1]) + b"\xff"


def packets(lines):
    return [m for m in lines if m.get("t") == "pkt"]


# --- the capture worker ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def traffic_capture():
    """One capture of mixed real traffic, shared by the tests below (each real
    capture costs its duration)."""
    started = time.time()

    def traffic():
        udp_to(53, dns_query("live-test.example.com"))
        udp_to(9999, b"noise-one")
        http_exchange(b"GET /secret/path?token=abc123 HTTP/1.1\r\nHost: live.test\r\nCookie: a=b\r\n\r\n")
        udp_to(123, bytes([0x23]) + bytes(47))

    lines = run_sniffer("capture_worker.py", "CAPTURE_CONFIG",
                        {"iface": LOOPBACK, "duration": 3, "payload": "full", "filter": {}}, traffic)
    return started, time.time(), lines


def test_loopback_packets_are_counted_once_not_as_leaving_and_arriving(traffic_capture):
    """lo hands every packet to a sniffer twice. Seen twice, each data packet's
    copy looks like a retransmission — so this also guards the TCP health check."""
    _, _, lines = traffic_capture
    assert not [p for p in packets(lines) if p["dir"] == "out"]
    requests_seen = [p for p in packets(lines) if p.get("app") == "http" and p["info"].startswith("GET")]
    assert len(requests_seen) == 1


def test_it_reads_real_packets_and_finishes_cleanly(traffic_capture):
    _, _, lines = traffic_capture
    assert lines[-1]["t"] == "end" and lines[-1]["reason"] == "finished"
    assert len(packets(lines)) > 10


def test_dns_ntp_and_udp_are_decoded_from_real_frames(traffic_capture):
    _, _, lines = traffic_capture
    infos = [p["info"] for p in packets(lines)]
    assert "A live-test.example.com?" in infos
    assert "NTP v4 client" in infos
    assert any(p["proto"] == "UDP" and p.get("dport") == 9999 for p in packets(lines))


def test_a_real_tcp_connection_shows_its_handshake_flags_and_no_trouble(traffic_capture):
    _, _, lines = traffic_capture
    tcp = [p for p in packets(lines) if p["proto"] == "TCP"]
    flags = {p["flags"] for p in tcp}
    assert "S" in flags and "SA" in flags and any("F" in f for f in flags)  # SYN, SYN-ACK, a FIN
    assert not [p for p in tcp if p.get("issues")]  # a clean local exchange has nothing wrong with it


def test_plain_http_is_read_without_its_query_string_or_cookie(traffic_capture):
    _, _, lines = traffic_capture
    [request] = [p for p in packets(lines) if p.get("app") == "http" and p["info"].startswith("GET")]
    assert request["name"] == "live.test" and request["info"] == "GET /secret/path?…  Host: live.test"
    assert not any("abc123" in p["info"] or "Cookie" in p["info"] for p in packets(lines))  # kept out of everything the list shows
    assert any(p.get("app") == "http" and p["info"].startswith("HTTP 200") for p in packets(lines))


def test_whole_packets_really_do_carry_the_payload_for_follow_stream(traffic_capture):
    _, _, lines = traffic_capture
    [request] = [p for p in packets(lines) if p.get("app") == "http" and p["info"].startswith("GET")]
    payload = bytes.fromhex(request["hex"])[request["poff"]:request["poff"] + request["plen"]]
    assert payload.startswith(b"GET /secret/path?token=abc123 HTTP/1.1")  # opted in, so it is there — and only here


def test_timestamps_come_from_the_kernel_and_are_in_order(traffic_capture):
    started, finished, lines = traffic_capture
    stamps = [p["ts"] for p in packets(lines)]
    assert stamps == sorted(stamps)
    assert started - 1 <= stamps[0] and stamps[-1] <= finished + 1
    assert any(abs(s - round(s)) > 1e-6 for s in stamps)  # sub-second precision, not whole seconds


def test_the_drop_counter_is_reported_each_second(traffic_capture):
    _, _, lines = traffic_capture
    ticks = [m for m in lines if m.get("t") == "tick"]
    assert ticks and all(isinstance(t["drops"], int) and t["drops"] >= 0 for t in ticks)
    assert sum(t["pkts"] for t in ticks) >= len(packets(lines))  # totals count at least every packet listed


def test_a_capture_filter_keeps_only_what_it_names():
    def traffic():
        udp_to(53, dns_query("only.this.example.com"))
        udp_to(9999, b"noise")
        http_exchange(b"GET / HTTP/1.1\r\nHost: noise.test\r\n\r\n")

    lines = run_sniffer("capture_worker.py", "CAPTURE_CONFIG",
                        {"iface": LOOPBACK, "duration": 2, "payload": "none", "filter": {"expr": "udp and port 53"}}, traffic)
    seen = packets(lines)
    assert seen and all(p["proto"] == "UDP" and 53 in (p["sport"], p["dport"]) for p in seen)
    assert sum(t["pkts"] for t in lines if t.get("t") == "tick") == len(seen)  # the totals respect the filter too


def test_headers_only_keeps_no_payload_even_of_real_http():
    def traffic():
        http_exchange(b"GET /private HTTP/1.1\r\nHost: h.test\r\n\r\nsecret-body")

    lines = run_sniffer("capture_worker.py", "CAPTURE_CONFIG", {"iface": LOOPBACK, "duration": 2, "payload": "none", "filter": {"expr": "tcp"}}, traffic)
    assert not any(b"secret-body" in bytes.fromhex(p["hex"]) or b"/private" in bytes.fromhex(p["hex"]) for p in packets(lines))


def test_promiscuous_mode_works_or_says_plainly_why_not():
    lines = run_sniffer("capture_worker.py", "CAPTURE_CONFIG",
                        {"iface": LOOPBACK, "duration": 1, "payload": "none", "promisc": True, "filter": {}}, lambda: udp_to(9999, b"x"))
    end = lines[-1]
    assert end["t"] == "end"
    assert end["reason"] == "finished" or "promiscuous" in end["reason"]  # never an unexplained crash


def test_an_interface_that_does_not_exist_is_reported_not_crashed_on():
    lines = run_sniffer("capture_worker.py", "CAPTURE_CONFIG", {"iface": "nonexistent0", "duration": 1}, lambda: None, lead=0.2)
    assert lines[-1]["t"] == "end" and "couldn't open the capture" in lines[-1]["reason"]


# --- the network watcher's kernel filter ---------------------------------------------------------

def _read_frames(sock: socket.socket, seconds: float) -> list[bytes]:
    frames, end = [], time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([sock], [], [], 0.1)
        if ready:
            frames.append(sock.recv(65535))
    return frames


def _kind(frame: bytes) -> str:
    """What a loopback frame is, for the assertions below."""
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0806:
        return "arp"
    if ethertype == 0x0800 and frame[23] == 17:
        ihl = (frame[14] & 0xF) * 4
        sport, dport = struct.unpack("!HH", frame[14 + ihl:14 + ihl + 4])
        return "dhcp" if {67, 68} & {sport, dport} else f"udp:{dport}"
    if ethertype == 0x0800:
        return f"ip:{frame[23]}"
    return f"eth:{ethertype:#06x}"


def test_the_kernel_accepts_the_watchers_filter_and_it_passes_only_arp_and_dhcp():
    import netwatch_worker as nw

    filtered = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    control = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # sees everything: proves the noise was sent
    try:
        nw.attach_filter(filtered)  # raises if the kernel rejects the program
        filtered.bind((LOOPBACK, 0))
        control.bind((LOOPBACK, 0))
        time.sleep(0.2)

        udp_to(67, b"dhcp-ish")
        udp_to(53, dns_query("noise.example.com"))
        udp_to(9999, b"noise")
        udp_to(6700, b"almost")  # contains "67" but is not port 67
        http_exchange(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        inject(arp_frame(bytes.fromhex("aabbcc000001"), "192.168.77.10", "192.168.77.1"))

        passed = [_kind(f) for f in _read_frames(filtered, 1.0)]
        everything = [_kind(f) for f in _read_frames(control, 0.3)]
    finally:
        filtered.close()
        control.close()

    assert "arp" in passed and "dhcp" in passed
    assert set(passed) <= {"arp", "dhcp"}, f"the filter let through: {sorted(set(passed) - {'arp', 'dhcp'})}"
    # The control socket is what makes that meaningful: the noise really was on the wire.
    assert {"udp:53", "udp:9999", "udp:6700"} <= set(everything)


def test_the_watcher_turns_real_arp_and_dhcp_into_events_and_ignores_everything_else():
    mac = bytes.fromhex("aabbcc00000a")

    def traffic():
        udp_to(9999, b"noise")
        http_exchange(b"GET / HTTP/1.1\r\nHost: noise\r\n\r\n")
        udp_from(67, 68, dhcp_offer())  # a server answering a client, ports and all
        inject(arp_frame(mac, "192.168.77.10", "192.168.77.1"))
        time.sleep(0.8)

    process = subprocess.Popen(
        [sys.executable, str(ROOT / "netwatch_worker.py")],
        cwd=ROOT, env={**os.environ, "NETWATCH_CONFIG": json.dumps({"iface": LOOPBACK})},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(0.6)
    traffic()
    process.terminate()  # the helper has no deadline of its own; the agent kills it
    out, err = process.communicate(timeout=10)
    events = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert events, f"nothing printed; stderr: {err[-400:]}"

    arps = [e for e in events if e["t"] == "arp"]
    dhcps = [e for e in events if e["t"] == "dhcp"]
    assert arps and arps[0]["ip"] == "192.168.77.10" and arps[0]["mac"] == "aa:bb:cc:00:00:0a"
    assert dhcps and dhcps[0]["type"] == "Offer" and dhcps[0]["server"] == "192.168.77.1" and dhcps[0]["yiaddr"] == "192.168.77.50"
    assert {e["t"] for e in events} <= {"arp", "dhcp", "beat", "end"}  # nothing from the TCP, DNS or noise traffic
    assert len(arps) == 1  # the same claim, seen on the way out and back in, is passed on once per window
