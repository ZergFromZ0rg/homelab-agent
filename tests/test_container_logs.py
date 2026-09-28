"""Container logs over a websocket, against the real daemon when there is
one; the refusals on fakes."""

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


@pytest.fixture
def web(monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    return TestClient(main.app)


def test_needs_the_agent_token(web, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "secret")
    with pytest.raises(WebSocketDisconnect) as closed:
        with web.websocket_connect("/containers/abc/logs") as ws:
            ws.receive_text()
    assert closed.value.code == 4401


docker = pytest.importorskip("docker")
try:
    _real = docker.from_env()
    _real.ping()
    _DOCKER = True
except Exception:  # noqa: BLE001
    _DOCKER = False


@pytest.mark.skipif(not _DOCKER, reason="no Docker daemon reachable")
def test_tail_then_follow_then_end(web, monkeypatch):
    monkeypatch.setattr(main, "client", _real)
    c = _real.containers.run(
        "alpine:3", ["sh", "-c", "for i in 1 2 3; do echo line-$i; done; sleep 2; echo late; sleep 1"],
        detach=True, labels={"homelab-agent-test": "logs"},
    )
    try:
        time.sleep(1)
        seen, control = b"", None
        with web.websocket_connect(f"/containers/{c.id}/logs?tail=100") as ws:
            while control is None:
                m = ws.receive()
                if m.get("bytes"):
                    seen += m["bytes"]
                elif m.get("text"):
                    control = json.loads(m["text"])
        assert b"line-1" in seen and b"line-3" in seen
        assert b"late" in seen  # followed past the tail
        assert control["type"] == "exit"

        got = web.get(f"/containers/{c.id}/logs/download")
        assert b"line-2" in got.content and got.headers["content-disposition"].startswith("attachment")
    finally:
        c.remove(force=True)
