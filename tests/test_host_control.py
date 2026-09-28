"""Host control: parsing what systemd and apt say, and what's refused.
The commands themselves run on real hosts; here `run` is a fake."""

import sys
from unittest import mock

import pytest

if "main" in sys.modules:
    import main  # noqa: F401
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main  # noqa: F401

import host_control
from host_control import HostError


@pytest.fixture(autouse=True)
def on(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENABLED", "1")


def fake_run(monkeypatch, output, code=0):
    calls = []

    def run(client, script, timeout=None):
        calls.append(script)
        return code, output

    monkeypatch.setattr(host_control, "run", run)
    return calls


def test_facts():
    facts = host_control.parse_facts(
        "failed:smartd.service nut.service \nreboot:1\npkg:apt\nupdates:53\nsecurity:4\nupgrading:inactive\n"
    )
    assert facts["failed_units"] == ["smartd.service", "nut.service"]
    assert facts["reboot_required"] is True and facts["os_updates"] == 53
    assert facts["security_updates"] == 4 and facts["upgrading"] is False


def test_services_listing_puts_failed_first(monkeypatch):
    fake_run(monkeypatch, (
        "cron.service loaded active running Regular background program processing daemon\n"
        "smartd.service loaded failed failed Self Monitoring and Reporting Technology\n"
        "docker.service loaded active running Docker Application Container Engine\n"
    ))
    rows = host_control.services(None)
    assert [r["unit"] for r in rows] == ["smartd.service", "cron.service", "docker.service"]
    assert rows[2]["protected"] is True


def test_actions_are_checked_and_quoted(monkeypatch):
    calls = fake_run(monkeypatch, "active\n")
    assert host_control.service_action(None, "cron.service", "restart")["active"] == "active"
    host_control.service_action(None, r"systemd-fsck@dev-disk\x2d1.service", "restart")
    assert "'systemd-fsck@dev-disk\\x2d1.service'" in calls[-1]

    with pytest.raises(HostError, match="cut this machine off"):
        host_control.service_action(None, "docker.service", "stop")
    with pytest.raises(HostError, match="isn't a service"):
        host_control.service_action(None, "x;reboot.service", "restart")
    with pytest.raises(HostError, match="start, stop or restart"):
        host_control.service_action(None, "cron.service", "mask")


def test_power_is_scheduled_not_immediate(monkeypatch):
    calls = fake_run(monkeypatch, "scheduled\n")
    assert host_control.power(None, "reboot") == {"scheduled": "reboot", "in_seconds": 5}
    assert calls[-1].startswith("systemd-run --on-active=5")
    with pytest.raises(HostError):
        host_control.power(None, "halt-and-catch-fire")


def test_the_upgrade_runs_as_a_systemd_unit(monkeypatch):
    calls = fake_run(monkeypatch, "started\n")
    host_control._facts.clear()
    host_control.start_upgrade(None)
    assert "systemd-run --unit=homelab-os-upgrade" in calls[-1]
    assert "--force-confold" in calls[-1]


def test_os_update_listing(monkeypatch):
    fake_run(monkeypatch, (
        "openssl/stable-security 3.5.1-1+deb13u2 amd64 [upgradable from: 3.5.1-1+deb13u1]\n"
        "tzdata/stable-updates 2026b-0+deb13u1 all [upgradable from: 2026a-0+deb13u1]\n"
    ))
    monkeypatch.setattr(host_control, "refresh_facts", lambda client: {})
    pkgs = host_control.os_updates(None)["packages"]
    assert [(p["name"], p["security"]) for p in pkgs] == [("openssl", True), ("tzdata", False)]


def test_off_means_off(monkeypatch):
    monkeypatch.delenv("TERMINAL_ENABLED")
    with pytest.raises(HostError, match="host control is off"):
        host_control.services(None)
