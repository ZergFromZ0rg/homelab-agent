"""The /terminal websocket. Docker is stubbed at import like the other route
tests; the round trips at the bottom use the real daemon when there is one."""

import json
import sys
import time
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import terminal


@pytest.fixture(autouse=True)
def _off(monkeypatch):
    monkeypatch.delenv("TERMINAL_ENABLED", raising=False)
    monkeypatch.setattr(main, "AGENT_TOKEN", "")


@pytest.fixture
def client():
    return TestClient(main.app)


def refusal(client, url, **kwargs):
    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect(url, **kwargs) as ws:
            ws.receive_text()
    return caught.value


def test_refused_until_the_host_opts_in(client):
    closed = refusal(client, "/terminal?container=abc")
    assert closed.code == 4403
    assert "TERMINAL_ENABLED" in closed.reason


def test_needs_the_agent_token(client, monkeypatch):
    monkeypatch.setenv("TERMINAL_ENABLED", "1")
    monkeypatch.setattr(main, "AGENT_TOKEN", "secret")

    assert refusal(client, "/terminal?container=abc").code == 4401
    closed = refusal(
        client, "/terminal?container=abc", headers={"X-Agent-Token": "wrong"}
    )
    assert closed.code == 4401


def test_a_container_shell_needs_a_container(client, monkeypatch):
    monkeypatch.setenv("TERMINAL_ENABLED", "1")
    assert refusal(client, "/terminal").code == 4400


def test_containers_payload_says_whether_shells_are_on(client, monkeypatch):
    assert client.get("/containers").json()["terminal"] is False
    monkeypatch.setenv("TERMINAL_ENABLED", "1")
    assert client.get("/containers").json()["terminal"] is True


def test_the_pid_marker_is_stripped_and_remembered():
    session = terminal.Session.__new__(terminal.Session)
    session.pid = None
    session._scanned = b""
    session._size = None

    out = session._strip_marker(b"\x1b]7788;4242\x07root@box:/# ")

    assert out == b"root@box:/# "
    assert session.pid == 4242


def test_a_chunk_that_is_only_the_marker_is_not_the_end():
    # Regression: the first recv is often just the marker; stripping it
    # left b"", which the reader took for the shell exiting.
    session = terminal.Session.__new__(terminal.Session)
    session.pid = None
    session._scanned = b""
    session._size = None
    session.sock = mock.MagicMock()
    session.sock.recv.side_effect = [b"\x1b]7788;99\x07", b"$ "]

    assert session.read() == b"$ "
    assert session.pid == 99


def test_it_stops_looking_for_a_marker_that_never_comes():
    session = terminal.Session.__new__(terminal.Session)
    session.pid = None
    session._scanned = b""

    session._strip_marker(b"x" * (terminal.PID_SEARCH_LIMIT + 1))

    assert session.pid == 0


def test_a_host_shell_logs_in_as_the_checkout_owner():
    cmd = terminal.host_command(1000)
    assert cmd[:5] == ["nsenter", "-t", "1", "-a", "--"]
    assert "getent passwd 1000" in cmd[-1]
    assert "su -l" in cmd[-1]
    # Announced inside nsenter, so it's the shell's PID, not nsenter's.
    assert cmd[-1].startswith("printf")


def test_a_root_owned_checkout_gets_a_plain_root_shell():
    assert "su -l" not in terminal.host_command(None)[-1]


def test_owner_uid(tmp_path):
    assert terminal.owner_uid(None) is None
    assert terminal.owner_uid(str(tmp_path / "missing")) is None
    uid = terminal.owner_uid(str(tmp_path))
    assert uid is None or uid == tmp_path.stat().st_uid


def test_sessions_are_capped(client, monkeypatch):
    monkeypatch.setenv("TERMINAL_ENABLED", "1")
    monkeypatch.setattr(terminal, "_active", terminal.MAX_SESSIONS)
    try:
        with client.websocket_connect("/terminal?container=abc") as ws:
            message = json.loads(ws.receive_text())
    finally:
        terminal._active = 0
    assert message["type"] == "error"
    assert "already has" in message["message"]


# --- against a real daemon --------------------------------------------------

docker = pytest.importorskip("docker")

try:
    _real = docker.from_env()
    _real.ping()
    _DOCKER = True
except Exception:  # noqa: BLE001
    _DOCKER = False

needs_docker = pytest.mark.skipif(not _DOCKER, reason="no Docker daemon reachable")


@pytest.fixture
def sleeper():
    container = _real.containers.run(
        "alpine:3", ["sleep", "120"], detach=True, auto_remove=True,
        labels={"homelab-agent-test": "terminal"},
    )
    yield container
    container.remove(force=True)


def read_until(session, needle: bytes, timeout=10.0) -> bytes:
    seen = b""
    deadline = time.monotonic() + timeout
    session.sock.settimeout(timeout)
    while needle not in seen and time.monotonic() < deadline:
        chunk = session.read()
        if not chunk:
            break
        seen += chunk
    return seen


@needs_docker
def test_a_real_shell_runs_commands_and_is_hung_up_on_close(sleeper):
    session = terminal.open_container(_real, sleeper.id)
    session.resize(100, 30)

    session.write(b"stty size; echo marker-$((6*7))\n")
    output = read_until(session, b"marker-42")

    assert b"marker-42" in output
    assert b"30 100" in output
    assert b"7788" not in output
    assert session.pid

    session.close()

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _real.api.exec_inspect(session.exec_id)["Running"]:
            break
        time.sleep(0.2)
    # Without the hang-up this shell would carry on after the tab closed.
    assert not _real.api.exec_inspect(session.exec_id)["Running"]


@needs_docker
def test_the_route_end_to_end(client, monkeypatch, sleeper):
    monkeypatch.setenv("TERMINAL_ENABLED", "1")
    monkeypatch.setattr(main, "client", _real)

    with client.websocket_connect(
        f"/terminal?container={sleeper.id}&cols=90&rows=20"
    ) as ws:
        ws.send_bytes(b"echo route-$((2+3)); exit 3\n")
        seen = b""
        control = None
        while control is None:
            message = ws.receive()
            if message.get("bytes"):
                seen += message["bytes"]
            elif message.get("text"):
                control = json.loads(message["text"])

    assert b"route-5" in seen
    assert control == {"type": "exit", "code": 3}
