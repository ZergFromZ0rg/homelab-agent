"""The /connections route itself.

``main`` opens a Docker client at import time, but nothing this route
touches needs one, so the client is stubbed and these run anywhere — no
daemon, no skip. Parsing and aggregation are covered in
``test_connections.py``.
"""

import sys
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:  # an earlier test already imported it for real
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import connections

TABLE = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 "
    "sport=51234 dport=443 packets=12 bytes=1440 src=1.1.1.1 dst=10.0.0.5 "
    "sport=443 dport=51234 packets=10 bytes=5000 [ASSURED] mark=0 use=1\n"
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(TABLE)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    connections.reset_cache()

    # Not a context manager on purpose: entering one runs the startup hook,
    # which spawns the container cache worker against the Docker client.
    yield TestClient(main.app)

    connections.reset_cache()


def test_returns_the_aggregated_table(client):
    body = client.get("/connections").json()

    assert body["available"] is True
    assert body["accounting"] is True
    assert body["flows_total"] == 1

    (peer,) = body["peers"]
    assert peer["proto"] == "tcp"
    assert peer["src"] == "10.0.0.5"
    assert peer["dst"] == "1.1.1.1"
    assert peer["dport"] == 443
    assert peer["orig_bytes"] == 1440 and peer["reply_bytes"] == 5000


def test_says_what_to_mount_when_the_table_is_missing(client, monkeypatch, tmp_path):
    monkeypatch.setenv("CONNTRACK_FILE", str(tmp_path / "absent"))
    monkeypatch.setattr(connections, "DEFAULT_PATHS", ())
    connections.reset_cache()

    body = client.get("/connections").json()

    assert body["available"] is False
    assert "mount" in body["reason"]
    assert "peers" not in body


def test_is_token_gated_unlike_the_other_read_routes(client, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")

    assert client.get("/connections").status_code == 401
    assert client.get(
        "/connections", headers={"X-Agent-Token": "wrong"}
    ).status_code == 401
    assert client.get(
        "/connections", headers={"X-Agent-Token": "sekret"}
    ).status_code == 200

    # /containers and /inventory stay open, as they are today.
    assert client.get("/containers").status_code == 200
