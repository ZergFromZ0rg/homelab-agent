"""LAN scan: the limits it enforces and the job it reports. The sweep itself
is driven with probes faked out and a real listening socket for the TCP
checks."""

import ipaddress
import json
import socket
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

import lan_scan

HOST = {
    "default": "eth0",
    "ifaces": [
        {"name": "lo", "ip": "127.0.0.1", "mask": "255.0.0.0"},
        {"name": "docker0", "ip": "172.17.0.1", "mask": "255.255.0.0"},
        {"name": "tailscale0", "ip": "100.64.0.5", "mask": "255.192.0.0"},
        {"name": "eth0", "ip": "192.168.1.10", "mask": "255.255.255.0"},
    ],
    "arp": [
        {"ip": "192.168.1.1", "flags": "0x2", "mac": "aa:bb:cc:00:00:01", "dev": "eth0"},
        {"ip": "192.168.1.77", "flags": "0x0", "mac": "00:00:00:00:00:00", "dev": "eth0"},
        {"ip": "10.9.9.9", "flags": "0x2", "mac": "aa:bb:cc:00:00:09", "dev": "eth1"},
    ],
}


@pytest.fixture(autouse=True)
def _reset():
    lan_scan._job = None
    yield
    lan_scan._job = None


def test_scans_the_default_private_lan_and_skips_docker_vpn_and_loopback():
    name, net, own = lan_scan.choose_network(HOST)
    assert (name, str(net), own) == ("eth0", "192.168.1.0/24", "192.168.1.10")


def test_refuses_public_and_oversized_networks():
    public = {"default": "eth0", "ifaces": [{"name": "eth0", "ip": "8.8.8.8", "mask": "255.255.255.0"}]}
    with pytest.raises(lan_scan.ScanError, match="no private"):
        lan_scan.choose_network(public)
    wide = {"default": "eth0", "ifaces": [{"name": "eth0", "ip": "10.0.0.5", "mask": "255.255.0.0"}]}
    with pytest.raises(lan_scan.ScanError, match="larger than a /22"):
        lan_scan.choose_network(wide)


def test_arp_gives_macs_only_for_complete_entries_inside_the_subnet():
    net = ipaddress.ip_network("192.168.1.0/24")
    assert lan_scan.arp_macs(HOST, net) == {"192.168.1.1": "aa:bb:cc:00:00:01"}


def test_probe_sees_an_open_port_and_a_refused_one_but_not_silence(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    monkeypatch.setattr(lan_scan, "LIVENESS_PORTS", (port,))
    assert lan_scan.probe("127.0.0.1") is True
    listener.close()
    assert lan_scan.probe("127.0.0.1") is True  # nothing listening: refused, still alive

    class Silent:
        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            return 110  # timed out

        def close(self):
            pass

    fake = mock.Mock(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM, socket=lambda *a: Silent())
    monkeypatch.setattr(lan_scan, "socket", fake)
    assert lan_scan.probe("192.0.2.1") is False


def test_open_ports_reports_a_listening_service(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    monkeypatch.setattr(lan_scan, "SERVICES", {port: "thing", 1: "nothing"})
    try:
        assert lan_scan.open_ports("127.0.0.1") == [{"port": port, "service": "thing"}]
    finally:
        listener.close()


def test_a_scan_collects_devices_macs_ports_and_names(monkeypatch):
    client = mock.MagicMock()
    client.containers.run.return_value = json.dumps(HOST).encode()
    monkeypatch.setattr(lan_scan.rebuild, "helper_image", lambda c: "img")
    alive = {"192.168.1.20", "192.168.1.30"}
    monkeypatch.setattr(lan_scan, "probe", lambda ip: ip in alive)
    monkeypatch.setattr(lan_scan, "open_ports", lambda ip: [{"port": 80, "service": "http"}] if ip == "192.168.1.20" else [])
    monkeypatch.setattr(lan_scan, "hostname", lambda ip: "nas.lan" if ip == "192.168.1.20" else None)

    first = lan_scan.start(client)
    assert first["state"] == "scanning" and first["subnet"] == "192.168.1.0/24"
    for _ in range(100):
        out = lan_scan.snapshot()
        if out["state"] != "scanning":
            break
        time.sleep(0.1)

    assert out["state"] == "done", out.get("error")
    by_ip = {d["ip"]: d for d in out["devices"]}
    # TCP finds .20 and .30, the ARP table adds the silent router, and the
    # host itself is listed.
    assert set(by_ip) == {"192.168.1.1", "192.168.1.10", "192.168.1.20", "192.168.1.30"}
    assert by_ip["192.168.1.1"]["mac"] == "aa:bb:cc:00:00:01" and by_ip["192.168.1.1"]["via"] == "arp"
    assert by_ip["192.168.1.20"]["hostname"] == "nas.lan"
    assert by_ip["192.168.1.20"]["ports"] == [{"port": 80, "service": "http"}]
    assert out["scanned"] == 254


def test_a_second_start_while_scanning_does_not_launch_another(monkeypatch):
    client = mock.MagicMock()
    lan_scan._job = {"state": "scanning", "devices": [], "subnet": "192.168.1.0/24"}
    assert lan_scan.start(client)["state"] == "scanning"
    client.containers.run.assert_not_called()


def test_routes(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    web = TestClient(main.app)
    assert web.get("/network/scan").json() == {"state": "idle", "devices": []}

    def refuse(client, iface=None):
        raise lan_scan.ScanError("no private LAN interface to scan on this host")

    monkeypatch.setattr(lan_scan, "start", refuse)
    resp = web.post("/network/scan", json={})
    assert resp.status_code == 400 and "no private" in resp.json()["error"]


def test_identity_lists_only_this_hosts_private_lan_addresses(monkeypatch):
    host = {
        "default": "eth0",
        "ifaces": [
            {"name": "docker0", "ip": "172.17.0.1", "mask": "255.255.0.0", "mac": "02:42:00:00:00:01"},
            {"name": "tailscale0", "ip": "100.64.0.5", "mask": "255.192.0.0", "mac": None},
            {"name": "eth0", "ip": "192.168.1.10", "mask": "255.255.255.0", "mac": "d8:5e:d3:42:10:10"},
        ],
        "arp": [],
    }
    client = mock.MagicMock()
    client.containers.run.return_value = json.dumps(host).encode()
    monkeypatch.setattr(lan_scan.rebuild, "helper_image", lambda c: "img")
    monkeypatch.setattr(lan_scan, "_ident", None)
    assert lan_scan.identity(client)["addresses"] == [
        {"iface": "eth0", "ip": "192.168.1.10", "mac": "d8:5e:d3:42:10:10"}
    ]
    lan_scan.identity(client)  # cached
    assert client.containers.run.call_count == 1


def test_identity_reports_the_default_gateway(monkeypatch):
    host = {"default": "eth0", "gateway": "192.168.1.1", "ifaces": [], "arp": []}
    client = mock.MagicMock()
    client.containers.run.return_value = json.dumps(host).encode()
    monkeypatch.setattr(lan_scan.rebuild, "helper_image", lambda c: "img")
    monkeypatch.setattr(lan_scan, "_ident", None)
    assert lan_scan.identity(client)["gateway"] == "192.168.1.1"


def test_helper_script_turns_the_route_table_entry_into_a_dotted_gateway():
    # /proc/net/route stores the gateway as little-endian hex: 0101A8C0 is 192.168.1.1
    import socket, struct
    assert socket.inet_ntoa(struct.pack("<L", int("0101A8C0", 16))) == "192.168.1.1"
    assert "struct.pack('<L', int(f[2], 16))" in lan_scan._HELPER_SCRIPT
