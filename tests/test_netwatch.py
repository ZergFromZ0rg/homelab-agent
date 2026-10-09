"""Network watch: the kernel filter (run through a small BPF interpreter), the
detector's rules, and the controller around a fake helper container."""

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

import capture_worker as cw
import netwatch
import netwatch_worker as nw

MAC_A, MAC_B, MAC_GW, MAC_GW2 = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b", "aa:bb:cc:00:00:01", "de:ad:be:ef:00:01"


# --- frames -----------------------------------------------------------------------

def _mac(text):
    return bytes.fromhex(text.replace(":", ""))


def eth(ethertype, payload, src=MAC_A, dst="ff:ff:ff:ff:ff:ff"):
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def arp(op, sha, spa, tha, tpa):
    return eth(0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, _mac(sha), socket.inet_aton(spa), _mac(tha), socket.inet_aton(tpa)), src=sha)


def ipv4(proto, payload, src="192.168.1.10", dst="192.168.1.1", ihl_words=5, frag=0):
    options = bytes(4 * (ihl_words - 5))
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl_words, 0, 20 + len(options) + len(payload), 1, frag, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + options + payload


def udp(sport, dport, payload=b"x" * 20, **kw):
    return eth(0x0800, ipv4(17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, **kw))


def tcp(sport, dport):
    return eth(0x0800, ipv4(6, struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x10, 1000, 0, 0)))


def dhcp_payload(kind, server=None, yiaddr="0.0.0.0", client=MAC_A):
    head = struct.pack("!BBBBIHH4s4s4s4s", 2 if kind in (2, 5, 6) else 1, 1, 6, 0, 0xCAFE, 0, 0, bytes(4),
                       socket.inet_aton(yiaddr), bytes(4), bytes(4))
    head += _mac(client) + bytes(10) + bytes(64) + bytes(128) + b"\x63\x82\x53\x63"
    options = bytes([53, 1, kind])
    if server:
        options += bytes([54, 4]) + socket.inet_aton(server)
    return head + options + b"\xff"


# --- a classic-BPF interpreter, to test the program the kernel will run -----------------

def run_bpf(program, packet: bytes) -> int:
    a = x = pc = 0

    def load(offset, size):
        if offset < 0 or offset + size > len(packet):
            return None
        return int.from_bytes(packet[offset:offset + size], "big")

    while pc < len(program):
        code, jt, jf, k = program[pc]
        pc += 1
        if code in (nw.LD_H_ABS, nw.LD_B_ABS, nw.LD_H_IND):
            size = 1 if code == nw.LD_B_ABS else 2
            value = load(k + (x if code == nw.LD_H_IND else 0), size)
            if value is None:
                return 0  # the kernel rejects a packet the program reads past the end of
            a = value
        elif code == nw.LDX_MSH:
            value = load(k, 1)
            if value is None:
                return 0
            x = 4 * (value & 0xF)
        elif code == nw.JEQ:
            pc += jt if a == k else jf
        elif code == nw.JSET:
            pc += jt if a & k else jf
        elif code == nw.RET_K:
            return k
        else:
            raise AssertionError(f"opcode {code:#x} isn't in the interpreter")
    raise AssertionError("fell off the end of the program")


@pytest.mark.parametrize("name,frame,accepted", [
    ("ARP request", arp(1, MAC_A, "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1"), True),
    ("ARP reply", arp(2, MAC_GW, "192.168.1.1", MAC_A, "192.168.1.10"), True),
    ("DHCP discover", udp(68, 67, src="0.0.0.0", dst="255.255.255.255"), True),
    ("DHCP offer", udp(67, 68, src="192.168.1.1", dst="255.255.255.255"), True),
    ("DHCP relay (67 to 67)", udp(67, 67), True),
    ("DHCP with IP options (header longer than 20)", udp(68, 67, ihl_words=7), True),
    ("DNS", udp(40000, 53), False),
    ("NTP", udp(51000, 123), False),
    ("TCP on port 67", tcp(51000, 67), False),
    ("TCP", tcp(51000, 443), False),
    ("UDP, port 67 only as an unrelated high port", udp(6700, 6800), False),
    ("later IP fragment of UDP", udp(68, 67, frag=0x00B9), False),
    ("IPv6", eth(0x86DD, bytes(60)), False),
    ("LLDP", eth(0x88CC, bytes(40)), False),
    ("a truncated frame", eth(0x0800, b"\x45\x00")[:20], False),
])
def test_the_kernel_filter_passes_arp_and_dhcp_and_nothing_else(name, frame, accepted):
    assert (run_bpf(nw.bpf_program(), frame) > 0) is accepted, name


def test_every_jump_in_the_program_lands_inside_it():
    program = nw.bpf_program()
    for pc, (code, jt, jf, _) in enumerate(program):
        if code in (nw.JEQ, nw.JSET):
            assert 0 <= pc + 1 + jt < len(program) and 0 <= pc + 1 + jf < len(program)
    assert program[-1][0] == nw.RET_K  # nothing can fall off the end


def test_the_filter_is_attached_as_a_sock_fprog():
    sock = mock.MagicMock()
    nw.attach_filter(sock)
    level, option, value = sock.setsockopt.call_args.args
    assert (level, option) == (socket.SOL_SOCKET, nw.SO_ATTACH_FILTER)
    assert struct.unpack("@H", value[:2])[0] == len(nw.bpf_program())  # sock_fprog.len


# --- the worker: events out of decoded frames ---------------------------------------------

def test_arp_and_dhcp_frames_become_events():
    request = cw.decode_frame(arp(1, MAC_A, "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1"), 1)
    assert nw.events_from(request) == [{"t": "arp", "ip": "192.168.1.10", "mac": MAC_A, "op": 1, "eth": MAC_A}]

    offer = cw.decode_frame(udp(67, 68, dhcp_payload(2, server="192.168.1.1", yiaddr="192.168.1.50"),
                                src="192.168.1.1", dst="255.255.255.255"), 1)
    [event] = nw.events_from(offer)
    assert (event["t"], event["type"], event["server"], event["yiaddr"], event["src"]) == (
        "dhcp", "Offer", "192.168.1.1", "192.168.1.50", "192.168.1.1")
    assert nw.events_from(cw.decode_frame(tcp(1, 2), 1)) == []


def test_the_arp_sender_hardware_address_is_kept_even_when_it_differs_from_the_ethernet_source():
    spoof = eth(0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, _mac(MAC_GW2), socket.inet_aton("192.168.1.1"),
                                    _mac(MAC_A), socket.inet_aton("192.168.1.10")), src=MAC_B)
    [event] = nw.events_from(cw.decode_frame(spoof, 1))
    assert (event["mac"], event["eth"]) == (MAC_GW2, MAC_B)  # judged on the claim, not the carrier


def _run_worker(monkeypatch, frames):
    emitted, clock = [], [1000.0]
    monkeypatch.setattr(nw, "emit", emitted.append)
    sock = mock.MagicMock()
    queue = list(frames)

    def recvfrom(size):
        if not queue:
            raise KeyboardInterrupt
        clock[0] += 1
        return queue.pop(0), ("eth0", 3, 0, 1, b"")

    sock.recvfrom = recvfrom
    monkeypatch.setattr(nw.socket, "AF_PACKET", 17, raising=False)  # Linux only; this may run on a Mac
    monkeypatch.setattr(nw.socket, "socket", lambda *a, **k: sock)
    monkeypatch.setattr(nw, "attach_filter", lambda s: None)
    monkeypatch.setattr(nw.time, "monotonic", lambda: clock[0])
    nw.run({"iface": "eth0"})
    return emitted


def test_the_worker_passes_a_claim_on_once_per_window_but_every_change(monkeypatch):
    same = arp(2, MAC_GW, "192.168.1.1", MAC_A, "192.168.1.10")
    changed = arp(2, MAC_GW2, "192.168.1.1", MAC_A, "192.168.1.10")
    out = _run_worker(monkeypatch, [same, same, same, changed])
    arps = [e for e in out if e["t"] == "arp"]
    assert [e["mac"] for e in arps] == [MAC_GW, MAC_GW2]  # the repeats were absorbed
    assert out[-1]["t"] == "end"


def test_a_frame_that_breaks_the_decoder_costs_one_frame(monkeypatch, capsys):
    real = cw.decode_frame

    def decode(frame, hatype):
        if frame == b"poison":
            raise RuntimeError("unforeseen")
        return real(frame, hatype)

    monkeypatch.setattr(cw, "decode_frame", decode)
    out = _run_worker(monkeypatch, [b"poison", arp(1, MAC_A, "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1")])
    assert [e["t"] for e in out].count("arp") == 1
    assert capsys.readouterr().err.count("Traceback") == 1


# --- the detector -----------------------------------------------------------------------------

T0 = 1_700_000_000.0


def detector(**saved):
    d = netwatch.Detector(saved or None, now=T0)
    d.gateway = "192.168.1.1"
    return d


def kinds(d):
    return sorted(f["kind"] for f in d.findings.values())


def test_the_gateway_changing_hands_is_bad_and_says_what_it_may_mean():
    d = detector()
    d.observe_arp("192.168.1.1", MAC_GW, T0)
    d.observe_arp("192.168.1.1", MAC_GW, T0 + 5)
    assert kinds(d) == [] or kinds(d) == ["new-device"]
    d.observe_arp("192.168.1.1", MAC_GW2, T0 + 10)
    [finding] = [f for f in d.findings.values() if f["kind"] == "gateway-changed"]
    assert finding["severity"] == "bad" and finding["previous"] == MAC_GW and finding["mac"] == MAC_GW2
    assert "replaced or reset the router" in finding["message"] and "spoofing" in finding["message"]
    assert finding in d.active(T0 + 20)


def test_a_duplicate_address_while_the_old_owner_is_active_is_a_warning():
    d = detector()
    d.observe_arp("192.168.1.20", MAC_A, T0)
    d.observe_arp("192.168.1.20", MAC_B, T0 + 60)
    [finding] = [f for f in d.findings.values() if f["kind"] == "arp-conflict"]
    assert finding["severity"] == "warn" and finding["previous"] == MAC_A


def test_an_address_reused_after_an_hour_of_quiet_is_only_information():
    d = detector()
    d.observe_arp("192.168.1.20", MAC_A, T0)
    d.observe_arp("192.168.1.20", MAC_B, T0 + 3 * 3600)
    [finding] = [f for f in d.findings.values() if f["kind"] == "address-reassigned"]
    assert finding["severity"] == "info"
    assert finding not in d.active(T0 + 3 * 3600)  # information never alerts


def test_the_same_conflict_is_one_finding_with_a_count_not_a_flood():
    d = detector()
    d.observe_arp("192.168.1.20", MAC_A, T0)
    for i in range(1, 6):
        d.observe_arp("192.168.1.20", MAC_B if i % 2 else MAC_A, T0 + i)
    conflicts = [f for f in d.findings.values() if f["kind"] == "arp-conflict"]
    assert len(conflicts) == 2  # one per direction of the flip
    assert sum(f["count"] for f in conflicts) == 5


def test_a_new_device_is_information_after_the_first_run_learns_the_network():
    d = detector()  # a first run: five minutes of learning
    d.observe_arp("192.168.1.30", MAC_A, T0 + 10)
    assert kinds(d) == []  # not announced while learning
    d.observe_arp("192.168.1.31", MAC_B, T0 + 600)
    [finding] = d.findings.values()
    assert finding["kind"] == "new-device" and finding["severity"] == "info" and finding["ip"] == "192.168.1.31"


def test_a_restart_remembers_and_does_not_relearn():
    d = detector()
    d.observe_arp("192.168.1.30", MAC_A, T0)
    again = netwatch.Detector(json.loads(json.dumps(d.export())), now=T0 + 99)
    again.gateway = "192.168.1.1"
    again.observe_arp("192.168.1.31", MAC_B, T0 + 100)  # straight away: not in a learning window
    assert [f["kind"] for f in again.findings.values()] == ["new-device"]
    again.observe_arp("192.168.1.30", MAC_B, T0 + 101)  # and a spoof right after the restart is caught
    assert "arp-conflict" in kinds(again)


@pytest.mark.parametrize("ip,mac", [
    ("0.0.0.0", MAC_A), ("169.254.1.1", MAC_A), ("224.0.0.1", MAC_A), ("8.8.8.8", MAC_A), ("127.0.0.1", MAC_A),
    ("192.168.1.5", "00:00:00:00:00:00"), ("192.168.1.5", "ff:ff:ff:ff:ff:ff"), ("192.168.1.5", "not-a-mac"),
    ("192.168.1.1", "00:00:5e:00:01:0a"),  # VRRP's virtual MAC moves between routers by design
])
def test_claims_that_are_not_devices_are_ignored(ip, mac):
    d = detector()
    d.observe_arp("192.168.1.1", MAC_GW, T0)
    d.observe_arp(ip, mac, T0 + 1)
    assert ip not in d.bindings or d.bindings[ip]["mac"] != mac
    assert not any(f["kind"] in ("gateway-changed", "arp-conflict") for f in d.findings.values())


def test_a_second_dhcp_server_is_a_warning_naming_both():
    d = detector()
    d.observe_dhcp({"type": "Offer", "server": "192.168.1.1", "eth": MAC_GW}, T0)
    d.observe_dhcp({"type": "ACK", "server": "192.168.1.1", "eth": MAC_GW}, T0 + 5)
    assert d.findings == {}
    d.observe_dhcp({"type": "Offer", "server": "192.168.1.77", "eth": MAC_B}, T0 + 60)
    [finding] = d.findings.values()
    assert finding["kind"] == "second-dhcp-server" and finding["severity"] == "warn"
    assert "192.168.1.77" in finding["title"] and "192.168.1.1" in finding["message"]


def test_dhcp_clients_and_other_messages_are_not_servers():
    d = detector()
    for kind in ("Discover", "Request", "Release", "Inform", "Decline", "message"):
        d.observe_dhcp({"type": kind, "server": "192.168.1.9", "eth": MAC_A}, T0)
    assert d.servers == {} and d.findings == {}
    d.observe_dhcp({"type": "Offer", "server": None, "src": "0.0.0.0", "eth": MAC_A}, T0)
    assert d.servers == {}


def test_a_finding_stops_being_active_after_an_hour_without_a_repeat():
    d = detector()
    d.observe_arp("192.168.1.1", MAC_GW, T0)
    d.observe_arp("192.168.1.1", MAC_GW2, T0 + 1)
    assert len(d.active(T0 + 10)) == 1
    assert d.active(T0 + 1 + netwatch.ACTIVE_SECONDS + 1) == []
    d.observe_arp("192.168.1.1", MAC_GW, T0 + 4000)  # flips back: a new finding for that direction
    d.observe_arp("192.168.1.1", MAC_GW2, T0 + 4001)  # and flips again: the first one is sighted a second time
    active = d.active(T0 + 4002)
    assert len(active) == 2 and sorted(f["count"] for f in active) == [1, 2]


def test_the_findings_list_is_bounded(monkeypatch):
    monkeypatch.setattr(netwatch, "MAX_FINDINGS", 5)
    d = detector()
    d.learning_until = 0
    for i in range(20):
        d.observe_arp(f"192.168.1.{i + 10}", f"aa:bb:cc:00:01:{i:02x}", T0 + i)
    assert len(d.findings) == 5


# --- the controller -----------------------------------------------------------------------------

class FakeHelper:
    def __init__(self, lines):
        self.lines, self.killed, self.removed, self.started = lines, False, False, False

    def attach(self, **kwargs):
        return self._stream()

    def _stream(self):
        for line in self.lines:
            yield ((line if isinstance(line, str) else json.dumps(line)) + "\n").encode()
        while not self.killed and getattr(self, "hold", False):
            time.sleep(0.01)

    def start(self):
        self.started = True

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(netwatch, "STATE_FILE", tmp_path / "netwatch.json")
    monkeypatch.setattr(netwatch, "RESTART_BACKOFF", (0.05, 0.05, 0.05))
    monkeypatch.setattr(netwatch.lan_scan, "identity", lambda c: {"default": "eth0", "gateway": "192.168.1.1"})
    monkeypatch.setattr(netwatch.rebuild, "helper_image", lambda c: "img")
    netwatch.disable()
    netwatch._detector = None
    netwatch._status.update(state="off", iface=None, since=None, error=None, beat=None)
    yield
    netwatch.disable()
    netwatch._detector = None


def client_with(*helpers):
    client = mock.MagicMock()
    client.containers.create.side_effect = list(helpers) + [FakeHelper([]) for _ in range(20)]
    client.containers.list.return_value = []
    return client


def wait_for(predicate, seconds=3):
    end = time.time() + seconds
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_the_controller_runs_the_helper_privately_and_feeds_the_detector():
    helper = FakeHelper([
        {"t": "arp", "ip": "192.168.1.1", "mac": MAC_GW, "op": 2, "eth": MAC_GW},
        {"t": "arp", "ip": "192.168.1.1", "mac": MAC_GW2, "op": 2, "eth": MAC_GW2},
        {"t": "dhcp", "type": "Offer", "server": "192.168.1.1", "src": "192.168.1.1", "eth": MAC_GW, "client": MAC_A},
        {"t": "beat", "ts": 1},
    ])
    helper.hold = True
    client = client_with(helper)
    netwatch.enable(client)
    assert wait_for(lambda: netwatch.snapshot()["active"])
    snap = netwatch.snapshot()
    assert snap["enabled"] and snap["state"] == "watching" and snap["iface"] == "eth0" and snap["gateway"] == "192.168.1.1"
    assert [f["kind"] for f in snap["active"]] == ["gateway-changed"]
    assert snap["dhcp_servers"][0]["ip"] == "192.168.1.1" and snap["devices"] >= 1

    kwargs = client.containers.create.call_args.kwargs
    assert kwargs["network_mode"] == "host" and kwargs["cap_add"] == ["NET_RAW"] and kwargs["cap_drop"] == ["ALL"]
    assert kwargs["log_config"]["Type"] == "none"  # no packet-derived output in Docker's logs
    assert json.loads(kwargs["environment"]["NETWATCH_CONFIG"]) == {"iface": "eth0"}
    assert helper.started

    netwatch.disable()
    assert wait_for(lambda: helper.killed) and netwatch.snapshot()["state"] == "off"


def test_the_choice_and_what_was_learned_survive_a_restart(tmp_path):
    helper = FakeHelper([{"t": "arp", "ip": "192.168.1.1", "mac": MAC_GW, "op": 2, "eth": MAC_GW}])
    helper.hold = True
    netwatch.enable(client_with(helper))
    assert wait_for(lambda: netwatch.snapshot()["devices"] == 1)
    netwatch._save(force=True)
    saved = json.loads((tmp_path / "netwatch.json").read_text())
    assert saved["enabled"] is True and saved["bindings"]["192.168.1.1"]["mac"] == MAC_GW
    netwatch.disable()
    assert json.loads((tmp_path / "netwatch.json").read_text())["enabled"] is False

    netwatch._detector = None
    netwatch.resume(client_with())  # was off: stays off
    assert netwatch.snapshot()["enabled"] is False
    (tmp_path / "netwatch.json").write_text(json.dumps({**saved, "enabled": True}))
    netwatch.resume(client_with(FakeHelper([])))
    assert netwatch.snapshot()["enabled"] is True and netwatch._detector.bindings["192.168.1.1"]["mac"] == MAC_GW


def test_a_helper_that_dies_is_restarted_and_a_crash_says_why():
    first = FakeHelper(["Traceback (most recent call last):", "OSError: [Errno 19] No such device"])
    second = FakeHelper([{"t": "beat", "ts": 1}])
    second.hold = True
    client = client_with(first, second)
    netwatch.enable(client)
    assert wait_for(lambda: client.containers.create.call_count >= 2)
    assert wait_for(lambda: netwatch.snapshot()["state"] == "watching")
    assert first.removed  # the dead helper is cleaned up


def test_a_helper_that_cannot_start_is_reported_and_retried():
    client = mock.MagicMock()
    client.containers.list.return_value = []
    client.containers.create.side_effect = RuntimeError("no such image")
    netwatch.enable(client)
    assert wait_for(lambda: netwatch.snapshot()["state"] == "error")
    assert "no such image" in netwatch.snapshot()["error"]
    assert wait_for(lambda: client.containers.create.call_count >= 2)  # it keeps trying, with a pause


def test_a_host_without_a_default_route_says_so(monkeypatch):
    monkeypatch.setattr(netwatch.lan_scan, "identity", lambda c: {"default": None, "gateway": None})
    netwatch.enable(client_with())
    assert wait_for(lambda: "no default route" in (netwatch.snapshot()["error"] or ""))


def test_turning_it_off_and_on_again_never_leaves_two_watchers():
    h1, h2 = FakeHelper([]), FakeHelper([])
    h1.hold = h2.hold = True
    client = client_with(h1, h2)
    netwatch.enable(client)
    assert wait_for(lambda: h1.started)
    netwatch.disable()
    netwatch.enable(client)
    assert wait_for(lambda: h2.started)
    assert wait_for(lambda: h1.killed)
    time.sleep(0.3)
    assert sum(1 for t in threading.enumerate() if t is netwatch._thread) == 1
    assert client.containers.create.call_count == 2  # the first supervisor did not relaunch after the disable


def test_lines_that_are_not_ours_or_are_malformed_do_no_harm():
    netwatch._detector = netwatch.Detector(None, now=T0)
    assert netwatch.handle("Traceback (most recent call last):") is False
    assert netwatch.handle('{"t": "mystery"}') is False
    assert netwatch.handle('{"t": "arp"}') is True  # ours, missing its fields
    assert netwatch.handle('{"t": "arp", "ip": 5, "mac": null}') is True


def test_routes_are_token_gated_and_toggle_the_watch(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "secret")
    http = TestClient(main.app)
    assert http.get("/netwatch").status_code == 401 and http.post("/netwatch", json={}).status_code == 401
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    calls = []
    monkeypatch.setattr(main.netwatch, "enable", lambda c: calls.append("on") or {"enabled": True})
    monkeypatch.setattr(main.netwatch, "disable", lambda c=None: calls.append("off") or {"enabled": False})
    assert http.post("/netwatch", json={"enabled": True}).json() == {"enabled": True}
    assert http.post("/netwatch", json={"enabled": False}).json() == {"enabled": False}
    assert http.post("/netwatch").json() == {"enabled": False}  # no body means off, never on
    assert calls == ["on", "off", "off"]
