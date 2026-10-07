"""Packet capture: the decoder is exercised on hand-built frames, the
controller with a fake helper container that prints the worker's JSON lines."""

import json
import socket
import struct
import sys
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


def test_filter_matches_host_port_and_protocol():
    pkt = w.decode_frame(eth(0x0800, ipv4(6, tcp(51000, 443, 0x10))), 1)
    assert w.matches(pkt, {})
    assert w.matches(pkt, {"host": "192.168.1.1", "port": 443, "proto": "tcp"})
    assert not w.matches(pkt, {"host": "10.0.0.1"})
    assert not w.matches(pkt, {"port": 80})
    assert not w.matches(pkt, {"proto": "udp"})


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

    def logs(self, **kwargs):
        for line in self.lines:
            yield (json.dumps(line) + "\n").encode()

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


def _client(container):
    client = mock.MagicMock()
    client.containers.run.return_value = container
    client.containers.list.return_value = []
    return client


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    capture._job = capture._container = None
    monkeypatch.setattr(capture.rebuild, "helper_image", lambda c: "img")
    monkeypatch.setattr(capture.lan_scan, "read_host", lambda c: {
        "default": "eth0", "ifaces": [{"name": "eth0", "ip": "192.168.1.10"}, {"name": "lo", "ip": "127.0.0.1"}],
    })
    yield
    capture._job = capture._container = None


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
            "flows": [["TCP", "192.168.1.1", 443, "192.168.1.10", 51000, 3, 300, 1, 2]]}
    container = FakeContainer([pkt, tick, tick, {"t": "end", "reason": "finished", "ts": 102.0}])
    client = _client(container)

    capture.start(client, {"duration": 30, "filter": {"proto": "tcp"}})
    out = _wait_done()

    assert out["state"] == "done" and out["iface"] == "eth0"
    assert out["totals"] == {"pkts": 6, "bytes": 600} and out["unlisted"] == 2
    assert out["protocols"]["TCP"] == {"pkts": 6, "bytes": 600}
    assert out["flows"][0]["pkts"] == 6 and out["flows"][0]["in"] == 4
    assert [p["n"] for p in out["packets"]] == [1]
    assert capture.snapshot(after=1)["packets"] == []  # polling only carries what is new
    time.sleep(0.1)
    assert container.removed
    run = client.containers.run.call_args
    assert run.kwargs["network_mode"] == "host" and run.kwargs["cap_add"] == ["NET_RAW"]
    assert run.kwargs["cap_drop"] == ["ALL"]
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
        def logs(self, **kwargs):
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
    client.containers.run.assert_not_called()


def test_pcap_is_a_valid_file_with_one_record_per_packet():
    frame = eth(0x0800, ipv4(6, tcp(51000, 443, 0x02)))
    capture._job = capture._fresh({"iface": "eth0", "filter": {}, "payload": False, "duration": 5})
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
