"""Settings from the dashboard: what is accepted, what is refused, and why.

The refusals carry most of the weight. This is the one surface where a
remote caller changes how the agent behaves, and the whole reason it is
safe is that it writes to a file the agent owns rather than to the
environment — so the tests that matter are the ones proving it stays
inside that box.
"""

import json

import pytest

import config


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    for key in list(config.BY_KEY) + ["CONFIG_WRITABLE"]:
        monkeypatch.delenv(key, raising=False)
    config.reload()
    yield
    config.reload()


@pytest.fixture
def writable(monkeypatch):
    monkeypatch.setenv("CONFIG_WRITABLE", "1")


# ---- the opt-in -----------------------------------------------------------


def test_a_host_does_not_accept_settings_by_default():
    with pytest.raises(config.ConfigError, match="CONFIG_WRITABLE"):
        config.update({"BACKUP_SOURCE_DIRS": "/home/zerg"})


def test_reading_works_even_when_writing_does_not():
    """The dashboard has to be able to show what is set and explain the
    rest, rather than showing an empty page."""
    snapshot = config.snapshot()

    assert snapshot["writable"] is False
    assert "CONFIG_WRITABLE" in snapshot["why_not"]
    assert len(snapshot["settings"]) == len(config.SETTINGS)
    assert all(s["editable"] is False for s in snapshot["settings"])


# ---- the overlay ----------------------------------------------------------


def test_a_setting_overrides_the_environment(writable, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/from/env")
    assert config.get("BACKUP_SOURCE_DIRS") == "/from/env"

    config.update({"BACKUP_SOURCE_DIRS": "/from/dashboard"})

    assert config.get("BACKUP_SOURCE_DIRS") == "/from/dashboard"


def test_clearing_a_setting_falls_back_to_the_environment(writable, monkeypatch):
    monkeypatch.setenv("BACKUP_SOURCE_DIRS", "/from/env")
    config.update({"BACKUP_SOURCE_DIRS": "/from/dashboard"})

    config.update({"BACKUP_SOURCE_DIRS": ""})

    assert config.get("BACKUP_SOURCE_DIRS") == "/from/env"


def test_settings_survive_a_restart(writable, tmp_path):
    config.update({"BACKUP_SOURCE_DIRS": "/home/zerg"})
    config.reload()

    assert config.get("BACKUP_SOURCE_DIRS") == "/home/zerg"
    assert json.loads((tmp_path / "config.json").read_text()) == {
        "BACKUP_SOURCE_DIRS": "/home/zerg"
    }


def test_the_file_never_touches_the_environment(writable, monkeypatch):
    """The safety story in one test: nothing here can change what compose
    or the container start with."""
    import os

    before = dict(os.environ)
    config.update({"BACKUP_SOURCE_DIRS": "/home/zerg", "REBUILD_ENABLED": True})

    assert dict(os.environ) == before


def test_source_says_where_a_value_came_from(writable, monkeypatch):
    monkeypatch.setenv("HOST_NAME", "bigboy")
    config.update({"BACKUP_SOURCE_DIRS": "/home/zerg"})

    by_key = {s["key"]: s for s in config.current()}

    assert by_key["BACKUP_SOURCE_DIRS"]["source"] == "dashboard"
    assert by_key["HOST_NAME"]["source"] == "environment"
    assert by_key["BACKUP_DIRS"]["source"] == "unset"


# ---- what is refused ------------------------------------------------------


def test_a_key_that_is_not_a_setting_is_refused(writable):
    with pytest.raises(config.ConfigError, match="not a setting"):
        config.update({"PATH": "/tmp"})


def test_a_host_scoped_setting_cannot_be_changed(writable):
    """A bind mount and a container runtime were fixed before this process
    existed. Accepting them would be a lie."""
    with pytest.raises(config.ConfigError, match="fixed by this container"):
        config.update({"BACKUP_HOST_DIR": "/home/zerg/backups"})

    with pytest.raises(config.ConfigError, match="fixed by this container"):
        config.update({"AGENT_RUNTIME": "nvidia"})


@pytest.mark.parametrize("path", ["/", "/etc", "/usr", "/var/run", "/var/lib/docker"])
def test_system_directories_are_refused(writable, path):
    """Naming one of these hands over the whole host, which is never what a
    backup wants."""
    with pytest.raises(config.ConfigError, match="system directory"):
        config.update({"BACKUP_SOURCE_DIRS": path})


def test_a_relative_path_is_refused(writable):
    with pytest.raises(config.ConfigError, match="absolute"):
        config.update({"BACKUP_SOURCE_DIRS": "home/zerg"})


def test_dot_dot_is_refused(writable):
    with pytest.raises(config.ConfigError, match=r"\.\."):
        config.update({"BACKUP_SOURCE_DIRS": "/home/zerg/../../etc"})


def test_a_url_must_be_one(writable):
    with pytest.raises(config.ConfigError, match="http"):
        config.update({"BACKUP_PUBLIC_URL": "thinkpad:8123"})


def test_a_number_out_of_range_is_refused(writable):
    with pytest.raises(config.ConfigError, match="at least"):
        config.update({"BACKUP_INTERVAL_HOURS": 0})

    with pytest.raises(config.ConfigError, match="at most"):
        config.update({"BACKUP_INTERVAL_HOURS": 10000})


def test_one_bad_field_applies_none_of_them(writable):
    """A settings form is submitted whole. Half-applying it would leave the
    agent in a state nobody asked for."""
    config.update({"BACKUP_SOURCE_DIRS": "/home/zerg"})

    with pytest.raises(config.ConfigError):
        config.update({"BACKUP_DIRS": "/srv/backups", "BACKUP_PUBLIC_URL": "nope"})

    assert config.get("BACKUP_DIRS") == "", "the good field must not have landed"
    assert config.get("BACKUP_SOURCE_DIRS") == "/home/zerg"


# ---- secrets --------------------------------------------------------------


def test_a_secret_can_be_set_but_never_read_back(writable):
    config.update({"GITHUB_TOKEN": "ghp_pretend"})

    shown = {s["key"]: s for s in config.current()}["GITHUB_TOKEN"]

    assert shown["value"] == ""
    assert shown["set"] is True
    assert config.get("GITHUB_TOKEN") == "ghp_pretend", "still usable internally"


def test_a_secret_is_not_logged(writable, caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="audit"):
        config.update({"GITHUB_TOKEN": "ghp_pretend"})

    assert "ghp_pretend" not in caplog.text
    assert "GITHUB_TOKEN" in caplog.text


# ---- types ----------------------------------------------------------------


def test_a_boolean_takes_the_shapes_a_form_sends(writable):
    for value in (True, "1", "true", "yes", "on"):
        config.update({"REBUILD_ENABLED": value})
        assert config.get("REBUILD_ENABLED") == "1", value

    for value in (False, "", "0", "no"):
        config.update({"REBUILD_ENABLED": value})
        assert config.get("REBUILD_ENABLED") == "", value


def test_a_path_list_is_normalised(writable):
    config.update({"BACKUP_SOURCE_DIRS": " /home/zerg/ , /srv/data \n/mnt/x/"})

    assert config.get("BACKUP_SOURCE_DIRS") == "/home/zerg,/srv/data,/mnt/x"


def test_applied_reports_only_what_changed(writable):
    config.update({"BACKUP_SOURCE_DIRS": "/home/zerg"})

    out = config.update({"BACKUP_SOURCE_DIRS": "/home/zerg", "BACKUP_DIRS": "/srv/b"})

    assert out["applied"] == ["BACKUP_DIRS"]


# ---- the routes -----------------------------------------------------------


@pytest.fixture
def client(monkeypatch):
    import sys
    from unittest import mock
    from fastapi.testclient import TestClient

    if "main" in sys.modules:
        import main
    else:
        with mock.patch("docker.from_env", return_value=mock.MagicMock()):
            import main

    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    return TestClient(main.app)


def test_the_config_route_lists_every_setting(client):
    body = client.get("/config").json()

    assert body["writable"] is False
    assert {s["key"] for s in body["settings"]} == set(config.BY_KEY)


def test_the_config_route_refuses_writes_until_the_host_opts_in(client):
    resp = client.put("/config", json={"BACKUP_SOURCE_DIRS": "/home/zerg"})

    assert resp.status_code == 400
    assert "CONFIG_WRITABLE" in resp.json()["detail"]


def test_the_config_route_applies_a_setting(client, writable):
    resp = client.put("/config", json={"settings": {"BACKUP_SOURCE_DIRS": "/home/zerg"}})

    assert resp.status_code == 200
    assert resp.json()["applied"] == ["BACKUP_SOURCE_DIRS"]
    assert config.get("BACKUP_SOURCE_DIRS") == "/home/zerg"


def test_a_bad_value_is_a_400_with_the_reason(client, writable):
    resp = client.put("/config", json={"settings": {"BACKUP_SOURCE_DIRS": "/etc"}})

    assert resp.status_code == 400
    assert "system directory" in resp.json()["detail"]


def test_the_config_routes_need_the_token(client, monkeypatch):
    import main

    monkeypatch.setattr(main, "AGENT_TOKEN", "sekret")

    assert client.get("/config").status_code == 401
    assert client.put("/config", json={}).status_code == 401


def test_a_setting_takes_effect_without_a_restart(client, writable):
    """The whole point: no .env, no compose, no recreate."""
    import rebuild

    assert rebuild.enabled() is False

    client.put("/config", json={"settings": {"REBUILD_ENABLED": True}})

    assert rebuild.enabled() is True


def test_the_passphrase_is_a_secret_that_can_be_set(writable):
    config.update({"BACKUP_PASSPHRASE": "correct horse battery staple"})

    shown = {s["key"]: s for s in config.current()}["BACKUP_PASSPHRASE"]

    assert shown["value"] == "", "never handed back"
    assert shown["set"] is True
    assert config.get("BACKUP_PASSPHRASE") == "correct horse battery staple"


def test_the_passphrase_is_marked_as_the_one_you_cannot_lose(writable):
    setting = config.BY_KEY["BACKUP_PASSPHRASE"]

    assert setting["danger"] is True
    assert "UNREADABLE" in setting["help"]
