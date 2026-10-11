import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import web_links


@pytest.fixture(autouse=True)
def _fresh():
    web_links.reset()
    yield
    web_links.reset()


# ---- real local servers ----------------------------------------------------


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def quiet(cls):
    cls.log_message = lambda *a, **k: None
    return cls


@pytest.fixture
def servers():
    made = []

    def make(handler):
        server = serve(quiet(handler))
        made.append(server)
        return server.server_address[1]

    yield make
    for server in made:
        server.shutdown()
        server.server_close()


def reply(h, status, location=None, body=b"x"):
    h.send_response(status)
    if location:
        h.send_header("Location", location)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class Plain(BaseHTTPRequestHandler):
    def do_GET(self):
        reply(self, 200)


class PiholeLike(BaseHTTPRequestHandler):
    """Root is a 403; the UI lives under /admin/ (which redirects to a login)."""

    def do_GET(self):
        if self.path.startswith("/admin"):
            reply(self, 302, "/admin/login")
        else:
            reply(self, 403)


class HomepageLike(BaseHTTPRequestHandler):
    """Fine by address, 400 for any other Host."""

    def do_GET(self):
        host = self.headers.get("Host", "")
        if host.startswith("127.0.0.1"):
            reply(self, 200)
        else:
            reply(self, 400, body=b'{"error":"Host validation failed"}')


class NeedsLogin(BaseHTTPRequestHandler):
    def do_GET(self):
        reply(self, 401)


class Broken(BaseHTTPRequestHandler):
    def do_GET(self):
        reply(self, 500)


def silent_port():
    """A listener that accepts and never says anything (a torrent port)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    held = []

    def accept_forever():
        try:
            while True:
                held.append(sock.accept())
        except OSError:
            pass  # the test closed the listener

    threading.Thread(target=accept_forever, daemon=True).start()
    return sock, sock.getsockname()[1]


def closed_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---- probe -----------------------------------------------------------------


def test_a_plain_web_ui(servers):
    r = web_links.probe("127.0.0.1", servers(Plain), "thinkpad")
    assert r["state"] == "web" and r["ok"] and r["path"] == "/" and r["status"] == 200


def test_a_403_root_finds_the_page_that_answers(servers):
    r = web_links.probe("127.0.0.1", servers(PiholeLike), "thinkpad")
    assert r["ok"] and r["path"] == "/admin/" and r["status"] == 302


def test_an_app_that_refuses_the_node_name_is_flagged_not_hidden(servers):
    r = web_links.probe("127.0.0.1", servers(HomepageLike), "thinkpad")
    assert r["state"] == "web" and not r["ok"] and r["host_rejected"] and r["status"] == 400


def test_the_request_carries_the_node_name_and_port(servers):
    seen = []

    class Spy(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Host"))
            reply(self, 200)

    port = servers(Spy)
    web_links.probe("127.0.0.1", port, "thinkpad")
    assert seen[0] == f"thinkpad:{port}"


def test_a_login_wall_is_a_working_link(servers):
    assert web_links.probe("127.0.0.1", servers(NeedsLogin), "n")["ok"]


def test_a_port_that_is_not_http_is_silent_and_a_dead_one_is_closed():
    sock, port = silent_port()
    try:
        assert web_links.probe("127.0.0.1", port, "n")["state"] == "silent"
    finally:
        sock.close()
    assert web_links.probe("127.0.0.1", closed_port(), "n")["state"] == "closed"


# ---- choosing between ports --------------------------------------------------


def web(status=200, scheme="http", ok=True, rejected=False, path="/"):
    return {"state": "web", "scheme": scheme, "path": path, "status": status, "ok": ok, "host_rejected": rejected}


def test_the_port_that_answers_beats_the_one_that_does_not():
    known, best = web_links.choose([(53, {"state": "silent"}), (8053, web(302, path="/admin/"))])
    assert known and best["port"] == 8053 and best["path"] == "/admin/"


def test_a_working_port_beats_a_refusing_one_even_on_a_common_port():
    known, best = web_links.choose([(80, web(400, ok=False, rejected=True)), (9999, web(200))])
    assert best["port"] == 9999


def test_http_beats_https_then_common_ports_then_lowest():
    assert web_links.choose([(9443, web(scheme="https")), (9000, web())])[1]["port"] == 9000
    assert web_links.choose([(7000, web()), (8080, web())])[1]["port"] == 8080
    assert web_links.choose([(7002, web()), (7001, web())])[1]["port"] == 7001


def test_known_none_only_when_every_port_connected():
    assert web_links.choose([(6881, {"state": "silent"})]) == (True, None)
    assert web_links.choose([(6881, {"state": "silent"}), (8080, {"state": "closed"})]) == (False, None)
    assert web_links.choose([(8080, {"state": "closed"})]) == (False, None)


# ---- the host's socket tables ------------------------------------------------

TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F65 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000 10 0 0 10 -1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000 10 0 0 10 -1
   2: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000 10 0 0 10 -1
   3: 0F02000A:0016 0102000A:E2B4 01 00000000:00000000 02:000AFAF0 00000000     0        0 1004 1 0000 20 0 0 10 -1
   4: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000 10 0 0 10 -1
"""


def fake_proc(tmp_path, processes):
    """``processes``: pid -> (cgroup text, [socket inodes])."""
    (tmp_path / "1" / "net").mkdir(parents=True)
    (tmp_path / "1" / "net" / "tcp").write_text(TCP)
    for pid, (cgroup, inodes) in processes.items():
        d = tmp_path / str(pid)
        (d / "fd").mkdir(parents=True, exist_ok=True)
        (d / "cgroup").write_text(cgroup)
        for n, inode in enumerate(inodes):
            (d / "fd" / str(n + 3)).symlink_to(f"socket:[{inode}]")
    return str(tmp_path)


def test_listeners_are_listen_state_only(tmp_path):
    """Row 3 of the table is an established connection and must not appear."""
    rows = web_links.read_listeners(fake_proc(tmp_path, {}))
    assert {(r["ip"], r["port"]) for r in rows} == {("0.0.0.0", 8037), ("127.0.0.1", 8080), ("0.0.0.0", 53), ("0.0.0.0", 80)}


def test_host_network_ports_are_the_ones_the_containers_own_processes_listen_on(tmp_path):
    cid = "a" * 64
    root = fake_proc(tmp_path, {
        500: (f"0::/system.slice/docker-{cid}.scope\n", [1001, 1003]),   # ours: 8037 and 53
        600: ("0::/system.slice/docker-" + "b" * 64 + ".scope\n", [1005]),  # someone else's: 80
        700: ("0::/system.slice/sshd.service\n", [1002]),                  # a host daemon on loopback
    })
    ports = {r["port"] for r in web_links.host_network_listeners(cid, root)}
    assert ports == {8037, 53}


def test_loopback_listeners_are_never_candidates(tmp_path):
    cid = "c" * 64
    root = fake_proc(tmp_path, {500: (f"/docker/{cid}\n", [1002])})  # owns only 127.0.0.1:8080
    assert web_links.host_network_listeners(cid, root) == []


# ---- candidates --------------------------------------------------------------


def test_published_ports_use_the_bound_address_or_the_host_gateway():
    attrs = {"HostConfig": {"NetworkMode": "default", "PortBindings": {
        "80/tcp": [{"HostIp": "", "HostPort": "8080"}],
        "443/tcp": [{"HostIp": "100.64.0.9", "HostPort": "8443"}],
        "9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9000"}],
        "6881/udp": [{"HostIp": "", "HostPort": "6881"}],
    }}}
    assert web_links.candidates(attrs, "x" * 64, "172.18.0.1") == [("172.18.0.1", 8080), ("100.64.0.9", 8443)]


def test_gateway_is_the_default_routes_next_hop():
    route = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
             "eth0\t00000000\t0112A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
             "eth0\t0012A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
    assert web_links.gateway(route) == "192.168.18.1"
    assert web_links.gateway("garbage") == "172.17.0.1"


# ---- the cache ---------------------------------------------------------------


class FakeContainer:
    def __init__(self, cid, name, ports, started="t1", status="running"):
        self.id, self.name, self.status = cid, name, status
        self.attrs = {"State": {"StartedAt": started}, "HostConfig": {"NetworkMode": "default", "PortBindings": ports}}
        self.reloads = 0

    def reload(self):
        self.reloads += 1


class FakeClient:
    def __init__(self, containers):
        self._c = containers
        self.containers = SimpleNamespace(list=lambda: list(self._c))


def test_refresh_probes_once_then_serves_from_the_cache(monkeypatch):
    calls = []
    monkeypatch.setattr(web_links, "gateway", lambda *_: "10.0.0.1")
    monkeypatch.setattr(web_links, "probe", lambda a, p, n: calls.append((a, p, n)) or web())
    c = FakeContainer("1" * 64, "app", {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]})
    client = FakeClient([c])

    assert web_links.lookup(c.id) == (False, None)  # nothing known before the first probe
    web_links.refresh(client, "thinkpad", now=1000)
    assert calls == [("10.0.0.1", 8080, "thinkpad")]
    known, found = web_links.lookup(c.id)
    assert known and found["port"] == 8080

    web_links.refresh(client, "thinkpad", now=1100)   # inside the TTL, same container
    assert len(calls) == 1


def test_a_recreated_container_is_probed_again_and_a_gone_one_forgotten(monkeypatch):
    calls = []
    monkeypatch.setattr(web_links, "gateway", lambda *_: "10.0.0.1")
    monkeypatch.setattr(web_links, "probe", lambda a, p, n: calls.append(p) or web())
    ports = {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}
    c = FakeContainer("1" * 64, "app", ports, started="t1")
    web_links.refresh(FakeClient([c]), "n", now=1000)

    c.attrs["State"]["StartedAt"] = "t2"  # restarted
    web_links.refresh(FakeClient([c]), "n", now=1010)
    assert len(calls) == 2

    web_links.refresh(FakeClient([]), "n", now=1020)
    assert web_links.lookup(c.id) == (False, None)


def test_a_container_with_nothing_to_try_is_known_to_have_no_link(monkeypatch):
    monkeypatch.setattr(web_links, "gateway", lambda *_: "10.0.0.1")
    c = FakeContainer("2" * 64, "db", {})
    web_links.refresh(FakeClient([c]), "n", now=1)
    assert web_links.lookup(c.id) == (True, None)


def test_an_unreachable_port_is_not_reported_and_is_retried_sooner(monkeypatch):
    calls = []
    monkeypatch.setattr(web_links, "gateway", lambda *_: "10.0.0.1")
    monkeypatch.setattr(web_links, "probe", lambda a, p, n: calls.append(p) or {"state": "closed"})
    c = FakeContainer("3" * 64, "slow", {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]})
    client = FakeClient([c])
    web_links.refresh(client, "n", now=1000)
    assert web_links.lookup(c.id) == (False, None)
    web_links.refresh(client, "n", now=1000 + web_links.TTL_UNKNOWN + 1)
    assert len(calls) == 2


def test_a_stopped_container_is_not_probed(monkeypatch):
    monkeypatch.setattr(web_links, "gateway", lambda *_: "10.0.0.1")
    monkeypatch.setattr(web_links, "probe", lambda *a: pytest.fail("probed a stopped container"))
    c = FakeContainer("4" * 64, "off", {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}, status="exited")
    web_links.refresh(FakeClient([c]), "n", now=1)
