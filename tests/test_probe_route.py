"""POST /probe: the dashboard's way of asking "can this host reach X?"."""

import socket
import sys
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import probes


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "tok")
    return TestClient(main.app)


HEAD = {"X-Agent-Token": "tok"}


@pytest.fixture
def listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    yield sock.getsockname()[1]
    sock.close()


def test_needs_the_agent_token(client):
    assert client.post("/probe", json={"type": "tcp", "target": "127.0.0.1:1"}).status_code == 401
    assert client.post("/probe", json={}, headers={"X-Agent-Token": "nope"}).status_code == 401


def test_tcp_probe_reports_what_this_host_saw(client, listener):
    up = client.post("/probe", json={"type": "tcp", "target": f"127.0.0.1:{listener}", "timeout": 2}, headers=HEAD)
    assert up.status_code == 200
    body = up.json()
    assert body["ok"] is True and body["detail"] == "connected" and body["ms"] is not None


def test_a_failed_probe_is_still_a_200_with_ok_false(client):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    down = client.post("/probe", json={"type": "tcp", "target": f"127.0.0.1:{port}"}, headers=HEAD)
    assert down.status_code == 200 and down.json() == {"ok": False, "ms": None, "detail": "connection refused"}


def test_dns_probe(client):
    body = client.post("/probe", json={"type": "dns", "target": "localhost"}, headers=HEAD).json()
    assert body["ok"] is True and body["detail"].startswith("resolved to")


@pytest.mark.parametrize("body,fragment", [
    ({"type": "gopher", "target": "x"}, "type must be one of"),
    ({"type": "tcp"}, "target is required"),
    ({"type": "tcp", "target": "x:1", "timeout": 99}, "between 1 and 30"),
    ({"type": "tcp", "target": "x:1", "timeout": "soon"}, "must be numbers"),
    ({"type": "keyword", "target": "http://x"}, "keyword is required"),
    ({"type": "http", "target": "http://x", "keyword_mode": "maybe"}, "keyword_mode"),
])
def test_bad_requests_are_rejected_with_a_reason(client, body, fragment):
    response = client.post("/probe", json=body, headers=HEAD)
    assert response.status_code == 400 and fragment in response.json()["error"]


def test_only_the_probe_fields_reach_the_probe(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(probes, "probe", lambda spec: seen.update(spec) or probes.Result(True, 1.0, "ok"))
    client.post("/probe", json={"type": "tcp", "target": "h:1", "group": "x", "command": "rm -rf /"}, headers=HEAD)
    assert set(seen) == {"type", "target", "timeout", "expect_status", "verify_tls", "keyword", "keyword_mode", "warn_days"}
