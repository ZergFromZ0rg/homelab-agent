"""Packet capture: the decoder is exercised on hand-built frames, the
controller with a fake helper container that prints the worker's JSON lines."""

import json
import socket
import struct
import sys
import threading
import time
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import capture
import capture_worker as w

CLIENT_MAC = bytes.fromhex("aabbcc000001")
SERVER_MAC = bytes.fromhex("aabbcc000002")


def ipv4(proto: int, payload: bytes, src="192.168.1.10", dst="192.168.1.1") -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def eth(ethertype: int, payload: bytes) -> bytes:
    return SERVER_MAC + CLIENT_MAC + struct.pack("!H", ethertype) + payload


def tcp(sport, dport, flags) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 64240, 0, 0)


def dns_query(name: str, qtype=1) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def test_tcp_syn_is_decoded_with_ports_and_flags():
    pkt = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x02))), 1)
    assert (pkt["proto"], pkt["src"], pkt["dst"]) == ("TCP", "192.168.1.10", "192.168.1.1")
    assert (pkt["sport"], pkt["dport"], pkt["flags"]) == (51000, 443, "S")
    assert pkt["hdr"] == 14 + 20 + 20  # ethernet + ip + tcp: payload not included


def test_dns_query_and_answer_are_named():
    query_body = dns_query("example.com")
    query = w.decode_frame(
        eth(0x0800, ipv4(17, struct.pack("!HHHH", 40000, 53, 8 + len(query_body), 0) + query_body)), 1
    )
    assert query["app"] == "dns" and query["info"] == "A example.com?"

    answer = dns_query("example.com")
    answer = answer[:2] + struct.pack("!H", 0x8180) + struct.pack("!HHHH", 1, 1, 0, 0) + answer[12:]
    answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    reply = w.decode_frame(
        eth(0x0800, ipv4(17, struct.pack("!HHHH", 53, 40000, 8 + len(answer), 0) + answer, src="192.168.1.1", dst="192.168.1.10")), 1
    )
    assert reply["info"] == "A example.com → 93.184.216.34"


def client_hello(name: str) -> bytes:
    sni = name.encode()
    ext_sni = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    ext_other = struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    exts = ext_other + ext_sni
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_tls_client_hello_names_the_server():
    pkt = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x18) + client_hello("jellyfin.example.com"))), 1)
    assert pkt["sni"] == "jellyfin.example.com" and pkt["app"] == "tls"
    assert pkt["info"] == "Client Hello → jellyfin.example.com"
    assert cf.compile_filter(cf.combine({"proto": "tls"}))(pkt)
    assert not cf.compile_filter(cf.combine({"proto": "dns"}))(pkt)
    assert pkt["hdr"] == 14 + 20 + 20  # the handshake itself is never stored


def test_other_tls_traffic_and_truncated_hellos_have_no_name():
    hello = client_hello("a.example.com")
    for payload in (b"\x17\x03\x03\x00\x10" + bytes(16), hello[:30], hello[:60], b""):
        pkt = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x18) + payload)), 1)
        assert "sni" not in pkt


def test_arp_request_reads_as_who_has():
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, CLIENT_MAC, socket.inet_aton("192.168.1.10"),
                      bytes(6), socket.inet_aton("192.168.1.99"))
    pkt = w.decode_frame(eth(0x0806, arp), 1)
    assert pkt["proto"] == "ARP" and pkt["info"] == "who has 192.168.1.99? tell 192.168.1.10"


def test_raw_ip_frames_from_tunnels_have_no_ethernet_header():
    pkt = w.decode_frame(ipv4(1, bytes([8, 0, 0, 0, 0, 0, 0, 0])), 65534)
    assert pkt["proto"] == "ICMP" and pkt["info"] == "echo request" and pkt["l2"] == 0


def test_garbage_and_truncated_frames_do_not_raise():
    assert w.decode_frame(b"\x00" * 5, 1) is None
    assert w.decode_frame(eth(0x0800, b"\x45\x00"), 1) is None
    assert w.decode_frame(eth(0x0800, ipv4(6, b"\x00" * 4)), 1)["proto"] == "TCP"


def test_the_older_host_port_proto_fields_become_one_expression():
    pkt = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x10))), 1)

    def passes(selected):
        expression = cf.combine(selected)
        return expression is None or cf.compile_filter(expression)(pkt)

    assert cf.combine({}) is None and passes({})
    assert passes({"host": "192.168.1.1", "port": 443, "proto": "tcp"})
    assert not passes({"host": "10.0.0.1"})
    assert not passes({"port": 80})
    assert not passes({"proto": "udp"})
    assert cf.combine({"proto": "icmpv6"}) == "icmp6"
    assert cf.combine({"host": "10.0.0.1", "expr": "port 80 or port 8080"}) == "host 10.0.0.1 and (port 80 or port 8080)"
    assert not passes({"host": "192.168.1.1", "expr": "port 80 or port 8080"})  # all of them must match


def test_both_directions_share_a_flow_key():
    out = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x10))), 1)
    back = w.decode_frame(eth(0x0800, ipv4(6, tcp(443, 51000, 0x10), src="192.168.1.1", dst="192.168.1.10")), 1)
    assert w.flow_key(out) == w.flow_key(back)


@pytest.mark.parametrize("raw,message", [
    ({"host": "not-an-ip"}, "isn't an IP"),
    ({"port": 70000}, "between 1 and 65535"),
    ({"port": "abc"}, "must be a number"),
    ({"proto": "gopher"}, "protocol must be"),
])
def test_bad_filters_are_refused(raw, message):
    with pytest.raises(capture.CaptureError, match=message):
        capture.validate_filter(raw)


def test_filter_is_normalised():
    assert capture.validate_filter({"host": " 192.168.1.5 ", "port": "443", "proto": "TCP"}) == {
        "host": "192.168.1.5", "port": 443, "proto": "tcp",
    }


class FakeContainer:
    def __init__(self, lines):
        self.lines = lines
        self.killed = False
        self.removed = False

    def attach(self, **kwargs):
        self.attached = True
        return self._stream()

    def _stream(self):
        for line in self.lines:  # a dict is a message from the worker, a str a stray line (a traceback)
            yield ((line if isinstance(line, str) else json.dumps(line)) + "\n").encode()

    def start(self):
        self.started = True

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


def _client(container):
    client = mock.MagicMock()
    client.containers.create.return_value = container
    client.containers.list.return_value = []
    return client


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    capture._job = capture._container = capture._interfaces_cache = None
    capture._starting = False
    monkeypatch.setattr(capture.rebuild, "helper_image", lambda c: "img")
    monkeypatch.setattr(capture.lan_scan, "read_host", lambda c: {
        "default": "eth0", "ifaces": [{"name": "eth0", "ip": "192.168.1.10"}, {"name": "lo", "ip": "127.0.0.1"}],
    })
    yield
    capture._job = capture._container = capture._interfaces_cache = None
    capture._starting = False


def _wait_done():
    for _ in range(100):
        out = capture.snapshot()
        if out["state"] != "capturing":
            return out
        time.sleep(0.05)
    raise AssertionError("capture never finished")


def test_a_capture_collects_packets_totals_flows_and_protocols():
    pkt = {"t": "pkt", "ts": 100.5, "len": 74, "hex": "aabb", "proto": "TCP", "src": "a", "dst": "b", "l2": 14}
    tick = {"t": "tick", "ts": 101.0, "pkts": 3, "bytes": 300, "protos": {"TCP": [3, 300]}, "skipped": 1,
            "flows": [["TCP", "192.168.1.1", 443, "192.168.1.10", 51000, 3, 300, 1, 2, "plex.example.com"]]}
    container = FakeContainer([pkt, tick, tick, {"t": "end", "reason": "finished", "ts": 102.0}])
    client = _client(container)

    capture.start(client, {"duration": 30, "filter": {"proto": "tcp"}})
    out = _wait_done()

    assert out["state"] == "done" and out["iface"] == "eth0"
    assert out["totals"] == {"pkts": 6, "bytes": 600} and out["unlisted"] == 2
    assert out["protocols"]["TCP"] == {"pkts": 6, "bytes": 600}
    assert out["flows"][0]["pkts"] == 6 and out["flows"][0]["in"] == 4
    assert out["flows"][0]["name"] == "plex.example.com"
    assert [p["n"] for p in out["packets"]] == [1]
    assert capture.snapshot(after=1)["packets"] == []  # polling only carries what is new
    time.sleep(0.1)
    assert container.removed
    run = client.containers.create.call_args
    assert run.kwargs["network_mode"] == "host" and run.kwargs["cap_add"] == ["NET_RAW"]
    assert run.kwargs["cap_drop"] == ["ALL"]
    # Nothing may be left in Docker's own logs: they'd hold every packet, payload included.
    assert run.kwargs["log_config"]["Type"] == "none"
    assert container.attached and container.started
    assert json.loads(run.kwargs["environment"]["CAPTURE_CONFIG"])["filter"] == {"proto": "tcp"}


def test_a_helper_error_is_reported():
    container = FakeContainer([{"t": "end", "reason": "the helper isn't allowed a raw socket (needs NET_RAW)", "ts": 1}])
    capture.start(_client(container), {})
    out = _wait_done()
    assert out["state"] == "error" and "NET_RAW" in out["error"]


def test_a_helper_that_vanishes_is_an_error_not_a_hang():
    capture.start(_client(FakeContainer([])), {})
    out = _wait_done()
    assert out["state"] == "error" and "unexpectedly" in out["error"]


def test_only_one_capture_at_a_time_and_stop_kills_the_helper():
    class Endless(FakeContainer):
        def _stream(self):
            while not self.killed:
                time.sleep(0.02)
            yield (json.dumps({"t": "end", "reason": "stopped", "ts": 1}) + "\n").encode()

    container = Endless([])
    client = _client(container)
    capture.start(client, {})
    with pytest.raises(capture.CaptureError, match="already running"):
        capture.start(client, {})
    assert capture.stop()["state"] == "stopped" and container.killed


@pytest.mark.parametrize("body,message", [
    ({"iface": "wlan9"}, "isn't a capturable interface"),
    ({"duration": 2}, "between 5 and 600"),
    ({"duration": 9999}, "between 5 and 600"),
    ({"duration": "soon"}, "number of seconds"),
])
def test_start_refuses_bad_requests_before_touching_docker(body, message):
    client = _client(FakeContainer([]))
    with pytest.raises(capture.CaptureError, match=message):
        capture.start(client, body)
    client.containers.create.assert_not_called()


def test_pcap_is_a_valid_file_with_one_record_per_packet():
    frame = eth(0x0800, ipv4(6, tcp(51000, 443, 0x02)))
    capture._job = capture._fresh({"iface": "eth0", "filter": {}, "payload": "none", "promisc": False, "duration": 5})
    capture._job["packets"] = [{"n": 1, "ts": 1700000000.25, "len": len(frame), "hex": frame[:54].hex(), "l2": 14}]
    data = capture.pcap()
    magic, major, minor, _, _, snaplen, link = struct.unpack("<IHHiIII", data[:24])
    assert (magic, major, minor, link) == (0xA1B2C3D4, 2, 4, 1)
    sec, usec, caplen, origlen = struct.unpack("<IIII", data[24:40])
    assert (sec, usec, caplen, origlen) == (1700000000, 250000, 54, len(frame))
    assert len(data) == 40 + 54


def test_routes_are_token_gated(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "secret")
    http = TestClient(main.app)
    for method, path in (("get", "/capture"), ("post", "/capture"), ("delete", "/capture"),
                         ("get", "/capture/pcap"), ("get", "/capture/interfaces")):
        assert getattr(http, method)(path).status_code == 401, path
    assert http.get("/capture", headers={"X-Agent-Token": "secret"}).json() == {"state": "idle"}


# --- filter expressions --------------------------------------------------------

import capture_filter as cf


def _pkt(frame):
    return w.decode_frame(frame, 1)


SYN = _pkt(eth(0x0800, ipv4(6, tcp(51000, 443, 0x02))))  # 192.168.1.10:51000 -> 192.168.1.1:443
UDP_DNS = _pkt(eth(0x0800, ipv4(17, struct.pack("!HHHH", 40000, 53, 8 + len(dns_query("a.com")), 0) + dns_query("a.com"), dst="8.8.8.8")))
HELLO = _pkt(eth(0x0800, ipv4(6, tcp(51000, 443, 0x18) + client_hello("plex.example.com"))))
PING = _pkt(eth(0x0800, ipv4(1, bytes([8, 0, 0, 0, 0, 0, 0, 0]))))


@pytest.mark.parametrize("expr,expected", [
    ("host 192.168.1.1", [True, False, True, True]),
    ("src host 192.168.1.1", [False, False, False, False]),
    ("dst host 8.8.8.8", [False, True, False, False]),
    ("port 443", [True, False, True, False]),
    ("dst port 53", [False, True, False, False]),
    ("src port 51000", [True, False, True, False]),
    ("tcp port 443 and not tls", [True, False, False, False]),
    ("portrange 50000-51000", [True, False, True, False]),
    ("net 192.168.1.0/24", [True, True, True, True]),
    ("dst net 8.8.0.0/16", [False, True, False, False]),
    ("udp or icmp", [False, True, False, True]),
    ("udp || icmp", [False, True, False, True]),
    ("not (port 443 or port 53)", [False, False, False, True]),
    ("! tcp", [False, True, False, True]),
    ("ip and not ip6", [True, True, True, True]),
    ("dns", [False, True, False, False]),
    ("tls", [False, False, True, False]),
    ("sni *.example.com", [False, False, True, False]),
    ("sni plex.example.com", [False, False, True, False]),
    ("sni *.plex.example.com", [False, False, True, False]),
    ("sni *.com", [False, False, True, False]),
    ("sni *z.example.com", [False, False, False, False]),
    ("sni other.example.com", [False, False, False, False]),
    ("ether host aa:bb:cc:00:00:01", [True, True, True, True]),
    ("ether dst host aa:bb:cc:00:00:01", [False, False, False, False]),
    ("len > 100", [False, False, True, False]),
    ("less 80", [True, True, False, True]),
    ("greater 100", [False, False, True, False]),
    ("TCP PORT 443", [True, False, True, False]),
])
def test_filter_expressions(expr, expected):
    predicate = cf.compile_filter(expr)
    assert [predicate(p) for p in (SYN, UDP_DNS, HELLO, PING)] == expected, expr


def test_and_binds_tighter_than_or():
    p = cf.compile_filter("icmp or tcp and port 80")  # icmp or (tcp and port 80)
    assert p(PING) and not p(SYN)


def test_arp_has_no_ports_and_ports_never_match_icmp():
    arp = _pkt(eth(0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, CLIENT_MAC, socket.inet_aton("192.168.1.10"), bytes(6), socket.inet_aton("192.168.1.99"))))
    assert cf.compile_filter("arp and host 192.168.1.99")(arp)
    assert not cf.compile_filter("port 1 or portrange 1-65535")(arp)
    assert not cf.compile_filter("port 443")(PING)


@pytest.mark.parametrize("expr,message", [
    ("", "empty"),
    ("host", "ends too soon"),
    ("host nope", "isn't an IP"),
    ("port 99999", "isn't a port"),
    ("portrange 80", "needs a range"),
    ("portrange 90-80", "backwards"),
    ("net 10.0.0.0/99", "isn't a network"),
    ("ether host zz", "isn't a MAC"),
    ("tcp[13] = 2", "isn't supported"),
    ("vlan", "isn't supported"),
    ("(port 80", "never closed"),
    ("port 80 port 443", "join conditions"),
    ("icmp port 80", "has no ports"),
    ("len ~ 5", "after 'len'"),
    ("frobnicate", "don't know"),
    ("host 1.2.3.4 &", "unexpected"),
    ("x" * 400, "longer than"),
    ("(" * 40 + "tcp" + ")" * 40, "nested"),
])
def test_bad_expressions_say_why(expr, message):
    with pytest.raises(cf.FilterError, match=message):
        cf.compile_filter(expr)


def test_the_agent_validates_the_expression_before_starting():
    assert capture.validate_filter({"expr": "  tcp and port 443 "}) == {"expr": "tcp and port 443"}
    with pytest.raises(capture.CaptureError, match="filter: .*isn't a port"):
        capture.validate_filter({"expr": "port 99999"})
    client = _client(FakeContainer([]))
    with pytest.raises(capture.CaptureError, match="filter:"):
        capture.start(client, {"filter": {"expr": "host"}})
    client.containers.create.assert_not_called()


def test_the_worker_applies_the_expression_together_with_the_simple_fields():
    flt = {"proto": "tcp", "expr": "port 443"}
    expression = cf.compile_filter(flt["expr"])
    keep = cf.compile_filter(cf.combine(flt))
    assert keep(SYN) and not keep(UDP_DNS) and not keep(PING)


# --- DHCP / NTP / HTTP ---------------------------------------------------------

def dhcp(kind: int, yiaddr="0.0.0.0", host=None, wanted=None) -> bytes:
    head = struct.pack("!BBBBIHH4s4s4s4s", 1, 1, 6, 0, 0xCAFE, 0, 0, bytes(4), socket.inet_aton(yiaddr), bytes(4), bytes(4))
    head += CLIENT_MAC + bytes(10) + bytes(64) + bytes(128) + b"\x63\x82\x53\x63"
    opts = bytes([53, 1, kind])
    if host:
        opts += bytes([12, len(host)]) + host.encode()
    if wanted:
        opts += bytes([50, 4]) + socket.inet_aton(wanted)
    return head + opts + b"\xff"


def udp(sport, dport, payload, src="192.168.1.10", dst="192.168.1.1"):
    return _pkt(eth(0x0800, ipv4(17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, src=src, dst=dst)))


def test_dhcp_messages_are_read():
    request = udp(68, 67, dhcp(3, host="living-room-tv", wanted="192.168.1.50"))
    assert request["app"] == "dhcp" and request["name"] == "living-room-tv"
    assert request["info"] == "DHCP Request wants 192.168.1.50 “living-room-tv” (aa:bb:cc:00:00:01)"
    offer = udp(67, 68, dhcp(2, yiaddr="192.168.1.50"), src="192.168.1.1", dst="255.255.255.255")
    assert offer["info"] == "DHCP Offer 192.168.1.50"
    assert udp(68, 67, b"\x00" * 300).get("app") is None  # not DHCP: no magic cookie


def test_ntp_client_and_server():
    client = udp(51000, 123, bytes([0x23]) + bytes(47))  # v4, mode 3
    assert client["app"] == "ntp" and client["info"] == "NTP v4 client"
    server = udp(123, 51000, bytes([0x24, 2]) + bytes(46))
    assert server["info"] == "NTP v4 server stratum 2"
    assert udp(51000, 123, b"short").get("app") is None


def http_pkt(payload: bytes, sport=51000, dport=80):
    return _pkt(eth(0x0800, ipv4(6, tcp(sport, dport, 0x18) + payload)))


def test_http_request_keeps_the_host_but_not_the_query_string():
    pkt = http_pkt(b"GET /api/items?token=SECRET&page=2 HTTP/1.1\r\nHost: nas.lan:8080\r\nCookie: a=b\r\n\r\n")
    assert pkt["app"] == "http" and pkt["name"] == "nas.lan:8080"
    assert pkt["info"] == "GET /api/items?…  Host: nas.lan:8080"
    assert "SECRET" not in json.dumps(pkt) and "Cookie" not in json.dumps(pkt)


def test_http_response_and_non_http():
    assert http_pkt(b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n", sport=80, dport=51000)["info"] == "HTTP 404 Not Found"
    assert http_pkt(b"GET garbage\r\n").get("app") is None
    assert http_pkt(b"\x00\x01binary").get("app") is None


# --- TCP health ----------------------------------------------------------------

def seg(seq, plen=0, flags=0x10, ack=1, win=1000, src_port=51000, dst_port=443):
    frame = eth(0x0800, ipv4(6, struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, win, 0, 0) + b"x" * plen))
    return w.decode_frame(frame, 1)


def test_tcp_health_flags_retransmits_gaps_resets_and_zero_windows():
    h = w.TcpHealth()
    assert h.check(seg(100, 0, 0x02)) == []                      # SYN
    assert h.check(seg(101, 10, 0x18)) == []                     # data 101..110
    assert h.check(seg(101, 10, 0x18)) == ["retransmit"]
    assert h.check(seg(111, 10, 0x18)) == []                     # in order again
    assert h.check(seg(200, 10, 0x18)) == ["gap"]
    assert h.check(seg(210, 0, 0x14)) == ["reset"]
    assert h.check(seg(300, 0, 0x10, win=0)) == ["zero-window"]


def test_duplicate_acks_need_three_identical_acks_and_data_resets_the_count():
    h = w.TcpHealth()
    got = [h.check(seg(1, 0, 0x10, ack=500)) for _ in range(4)]
    assert got == [[], [], ["dup-ack"], ["dup-ack"]]
    assert h.check(seg(1, 0, 0x10, ack=900)) == []


def test_a_keep_alive_probe_is_not_a_retransmission():
    h = w.TcpHealth()
    h.check(seg(100, 10, 0x18))               # next = 110
    assert h.check(seg(109, 1, 0x10)) == []   # one byte at next-1


def test_each_direction_and_each_connection_is_tracked_separately():
    h = w.TcpHealth()
    h.check(seg(100, 10, 0x18))
    assert h.check(seg(100, 10, 0x18, src_port=51001)) == []  # another connection
    reply = w.decode_frame(eth(0x0800, ipv4(6, struct.pack("!HHIIBBHHH", 443, 51000, 100, 1, 5 << 4, 0x18, 1000, 0, 0) + b"x" * 5, src="192.168.1.1", dst="192.168.1.10")), 1)
    assert h.check(reply) == []                                # the reverse direction


def test_tcp_payload_length_ignores_ethernet_padding():
    frame = eth(0x0800, ipv4(6, tcp(51000, 443, 0x10))) + b"\x00" * 6
    assert w.decode_frame(frame, 1)["plen"] == 0


# --- kernel side (faked: AF_PACKET only exists on Linux) -------------------------

def test_kernel_timestamp_is_taken_from_the_ancillary_data():
    class Sock:
        def recvmsg(self, size, anc):
            stamp = struct.pack("qq", 1700000000, 250_000_000)
            return b"frame", [(socket.SOL_SOCKET, w.SO_TIMESTAMPNS, stamp)], 0, ("eth0", 3, 0, 1, b"")
    frame, addr, stamp = w.read_packet(Sock(), True)
    assert (frame, addr[0], stamp) == (b"frame", "eth0", 1700000000.25)

    class Plain:
        def recvmsg(self, size, anc):
            return b"f", [], 0, ("eth0", 3, 0, 1, b"")
    assert w.read_packet(Plain(), False)[2] is None


def test_kernel_drop_counter_is_the_second_field():
    class Sock:
        def getsockopt(self, level, name, size):
            return struct.pack("II", 900, 17)
    assert w.kernel_drops(Sock()) == 17

    class Refuses:
        def getsockopt(self, *a):
            raise OSError
    assert w.kernel_drops(Refuses()) == 0


# --- controller: options, drops and issues -----------------------------------------

@pytest.mark.parametrize("body,message", [
    ({"payload": "everything"}, "payload must be one of"),
    ({"promisc": True, "iface": "any"}, "promiscuous mode needs one interface"),
])
def test_new_option_validation(body, message):
    client = _client(FakeContainer([]))
    with pytest.raises(capture.CaptureError, match=message):
        capture.start(client, body)
    client.containers.create.assert_not_called()


def test_options_reach_the_helper_and_the_snapshot_and_a_boolean_payload_still_works():
    client = _client(FakeContainer([{"t": "end", "reason": "finished", "ts": 1}]))
    capture.start(client, {"payload": "full", "promisc": True, "iface": "eth0"})
    config = json.loads(client.containers.create.call_args.kwargs["environment"]["CAPTURE_CONFIG"])
    assert (config["payload"], config["promisc"]) == ("full", True)
    out = _wait_done()
    assert (out["payload"], out["promisc"]) == ("full", True)
    capture._job = capture._container = None
    client = _client(FakeContainer([]))
    capture.start(client, {"payload": True})
    assert json.loads(client.containers.create.call_args.kwargs["environment"]["CAPTURE_CONFIG"])["payload"] == "64"


def test_drops_and_tcp_issues_are_summed_per_capture_and_per_flow():
    tick = {"t": "tick", "ts": 5.0, "pkts": 2, "bytes": 200, "protos": {}, "drops": 4, "issues": {"retransmit": 2},
            "flows": [["TCP", "a", 1, "b", 2, 2, 200, 1, 1, "x.example.com", {"retransmit": 2}]]}
    capture.start(_client(FakeContainer([tick, tick, {"t": "end", "reason": "finished", "ts": 6}])), {})
    out = _wait_done()
    assert out["drops"] == 8 and out["issues"] == {"retransmit": 4}
    assert out["flows"][0]["issues"] == {"retransmit": 4} and out["flows"][0]["name"] == "x.example.com"


def test_snapshot_route_takes_a_limit(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    capture._job = capture._fresh({"iface": "eth0", "filter": {}, "payload": "none", "promisc": False, "duration": 5})
    capture._job["packets"] = [{"n": n, "ts": n, "len": 1, "hex": ""} for n in range(1, 11)]
    capture._job["seq"] = 10
    http = TestClient(main.app)
    assert len(http.get("/capture", params={"limit": 3}).json()["packets"]) == 3
    assert len(http.get("/capture", params={"limit": 99999}).json()["packets"]) == 10


# --- the filter language, new words ----------------------------------------------

def test_new_protocols_problems_and_name_in_filters():
    dhcp_pkt = udp(68, 67, dhcp(3, host="tv"))
    web = http_pkt(b"GET / HTTP/1.1\r\nHost: Nas.LAN\r\n\r\n")
    bad = dict(SYN, issues=["retransmit"])
    for expr, pkt, want in [
        ("dhcp", dhcp_pkt, True), ("http", web, True), ("ntp", dhcp_pkt, False),
        ("name tv", dhcp_pkt, True), ("name nas.lan", web, True), ("name *.lan", web, True), ("name *.local", web, False),
        ("name *.example.com", HELLO, True), ("sni nas.lan", web, False),
        ("retransmit", bad, True), ("reset", bad, False), ("problem", bad, True),
        ("problem", SYN, False), ("tcp and not problem", SYN, True),
    ]:
        assert cf.compile_filter(expr)(pkt) is want, expr


# --- review fixes -------------------------------------------------------------------

def test_a_helper_that_crashes_says_why():
    capture.start(_client(FakeContainer(["Traceback (most recent call last):", 'ImportError: no module named "capture_filter"'])), {})
    out = _wait_done()
    assert out["state"] == "error" and "capture_filter" in out["error"]


def test_two_simultaneous_starts_start_one_sniffer(monkeypatch):
    gate = threading.Event()
    real = capture._validated

    def slow(client, body):
        gate.wait(2)  # the second request arrives while the first is still validating
        return real(client, body)

    monkeypatch.setattr(capture, "_validated", slow)
    client = _client(FakeContainer([{"t": "end", "reason": "finished", "ts": 1}]))
    results = []

    def attempt():
        try:
            capture.start(client, {})
            results.append("started")
        except capture.CaptureError as error:
            results.append(str(error))

    first = threading.Thread(target=attempt)
    first.start()
    time.sleep(0.1)
    attempt()  # refused on the spot, without waiting
    gate.set()
    first.join(3)
    assert sorted(results) == ["a capture is already running — stop it first", "started"]
    assert client.containers.create.call_count == 1
    assert capture._starting is False


def test_a_failed_start_releases_the_reservation():
    client = _client(FakeContainer([]))
    client.containers.create.side_effect = RuntimeError("no such image")
    with pytest.raises(capture.CaptureError, match="couldn't start the capture helper"):
        capture.start(client, {})
    assert capture._starting is False
    client.containers.create.side_effect = None
    capture.start(client, {})  # not stuck


def test_a_helper_that_cannot_attach_is_removed_not_leaked():
    container = FakeContainer([])
    container.attach = lambda **k: (_ for _ in ()).throw(RuntimeError("daemon went away"))
    with pytest.raises(capture.CaptureError, match="daemon went away"):
        capture.start(_client(container), {})
    assert container.removed and not getattr(container, "started", False)


def test_interfaces_are_listed_once_per_half_minute(monkeypatch):
    calls = []
    host = {"default": "eth0", "ifaces": [{"name": "eth0", "ip": "192.168.1.10"}]}
    monkeypatch.setattr(capture.lan_scan, "read_host", lambda c: calls.append(1) or host)
    capture.interfaces(None)
    capture.interfaces(None)
    assert len(calls) == 1
    capture._interfaces_cache = (time.monotonic() - capture.INTERFACES_TTL - 1, capture._interfaces_cache[1])
    capture.interfaces(None)
    assert len(calls) == 2


def test_a_poll_never_drops_packets_however_many_arrived():
    capture._job = capture._fresh({"iface": "eth0", "filter": {}, "payload": "full", "promisc": False, "duration": 5})
    capture._job["packets"] = [{"n": n, "ts": n, "len": 1, "hex": ""} for n in range(1, 1501)]
    capture._job["seq"] = 1500
    assert len(capture.snapshot(0)["packets"]) == 1500
    assert [p["n"] for p in capture.snapshot(1000)["packets"]] == list(range(1001, 1501))


def test_lines_from_the_helper_that_are_not_ours_or_are_malformed_do_no_harm():
    job = capture._fresh({"iface": "eth0", "filter": {}, "payload": "none", "promisc": False, "duration": 5})
    capture._job = job
    assert capture._ingest(job, "Traceback (most recent call last):") is False
    assert capture._ingest(job, '{"t": "mystery"}') is False
    assert capture._ingest(job, "[1, 2]") is False
    assert capture._ingest(job, '{"t": "tick"}') is True  # ours, but missing its fields
    assert capture._ingest(job, '{"t": "tick", "ts": 1, "pkts": 1, "bytes": 1, "flows": [[1, 2]]}') is True
    assert job["state"] == "capturing"  # and the capture carried on


# --- the sniffer loop, with a fake socket ----------------------------------------------

def _run_worker(monkeypatch, frames, config=None):
    """Run ``run()`` over (frame, pkttype) pairs; returns the emitted messages."""
    emitted = []
    monkeypatch.setattr(w, "emit", emitted.append)
    monkeypatch.setattr(w, "open_socket", lambda iface, promisc: (mock.MagicMock(), True))
    monkeypatch.setattr(w, "kernel_drops", lambda sock: 0)
    queue = list(frames)

    def read(sock, stamped):
        if not queue:
            raise KeyboardInterrupt  # ends the loop the way a stop would
        frame, pkttype = queue.pop(0)
        return frame, ("eth0", 3, pkttype, 1, b""), 1700000000.5

    monkeypatch.setattr(w, "read_packet", read)
    w.run({"iface": "eth0", "duration": 5, **(config or {})})
    return emitted


def test_a_packet_nobody_anticipated_costs_one_packet_not_the_capture(monkeypatch, capsys):
    real = w.decode_frame
    poison = b"poison"

    def decode(frame, hatype):
        if frame == poison:
            raise RuntimeError("unforeseen packet")
        return real(frame, hatype)

    monkeypatch.setattr(w, "decode_frame", decode)
    good = eth(0x0800, ipv4(6, tcp(51000, 443, 0x02)))
    out = _run_worker(monkeypatch, [(good, 0), (poison, 0), (poison, 0), (good, 0)])
    assert [m["t"] for m in out].count("pkt") == 2
    assert out[-1]["t"] == "end" and out[-1]["reason"] == "stopped"
    assert capsys.readouterr().err.count("Traceback") == 1  # reported once, not per packet


def test_a_packets_direction_and_kernel_timestamp(monkeypatch):
    frame = eth(0x0800, ipv4(6, tcp(51000, 443, 0x02)))
    out = _run_worker(monkeypatch, [(frame, 0), (frame, 4), (frame, 3)])
    packets = [m for m in out if m["t"] == "pkt"]
    assert [p["dir"] for p in packets] == ["in", "out", "other"]
    assert packets[0]["ts"] == 1700000000.5


def test_the_worker_filters_with_the_combined_expression_and_counts_only_matches(monkeypatch):
    syn = eth(0x0800, ipv4(6, tcp(51000, 443, 0x02)))
    ping = eth(0x0800, ipv4(1, bytes([8, 0, 0, 0, 0, 0, 0, 0])))
    out = _run_worker(monkeypatch, [(syn, 0), (ping, 0), (syn, 0)], {"filter": {"proto": "tcp", "expr": "port 443"}})
    assert [m["proto"] for m in out if m["t"] == "pkt"] == ["TCP", "TCP"]


def test_arp_for_other_hardware_is_not_misread_as_ethernet_arp():
    infiniband = struct.pack("!HHBBH6s4s6s4s", 32, 0x0800, 6, 4, 1, CLIENT_MAC, bytes(4), bytes(6), bytes(4))
    assert w.decode_frame(eth(0x0806, infiniband), 1)["proto"] == "eth 0x0806"


def test_dhcp_between_relay_and_server_is_read_too():
    pkt = udp(67, 67, dhcp(1), src="10.0.0.1", dst="192.168.1.1")
    assert pkt["app"] == "dhcp" and pkt["info"].startswith("DHCP Discover")
