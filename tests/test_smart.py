"""Disk health: what counts as a warning, what happens to a drive that is asleep,
and the helper round trip. smartctl's JSON is written out by hand in its own shape."""

import json
import subprocess
from types import SimpleNamespace

import pytest

import smart


def ata(attrs=None, passed=True, rotation=7200, temp=34, name="/dev/sda", model="ST1000DM010-2EP102"):
    table = [{"id": i, "name": n, "value": 100, "worst": 100, "thresh": 10, "when_failed": "", "raw": {"value": raw}}
             for i, n, raw in (attrs or [])]
    return {
        "device": {"name": name, "type": "sat", "protocol": "ATA"}, "model_name": model,
        "user_capacity": {"bytes": 1_000_204_886_016}, "rotation_rate": rotation,
        "smart_status": {"passed": passed}, "temperature": {"current": temp}, "power_on_time": {"hours": 12345},
        "ata_smart_attributes": {"table": table},
    }


def nvme(**over):
    log = {"critical_warning": 0, "temperature": 38, "available_spare": 100, "available_spare_threshold": 10,
           "percentage_used": 3, "media_errors": 0, "power_on_hours": 4000, **over}
    return {
        "device": {"name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"}, "model_name": "KINGSTON SNV3S1000G",
        "user_capacity": {"bytes": 1_000_204_886_016}, "smart_status": {"passed": True},
        "temperature": {"current": log["temperature"]}, "nvme_smart_health_information_log": log,
    }


HEALTHY = [(5, "Reallocated_Sector_Ct", 0), (197, "Current_Pending_Sector", 0), (198, "Offline_Uncorrectable", 0),
           (199, "UDMA_CRC_Error_Count", 0)]


def health(raw):
    return smart.assess(raw)["health"], smart.assess(raw)["reasons"]


# ---- the judgement -------------------------------------------------------


def test_a_clean_hard_disk_is_ok_and_described():
    out = smart.assess(ata(HEALTHY))
    assert (out["health"], out["kind"], out["size_gb"], out["temperature_c"], out["power_on_hours"]) == ("ok", "hdd", 1000, 34, 12345)
    assert out["reasons"] == []


def test_a_clean_nvme_is_ok_and_reports_its_wear():
    out = smart.assess(nvme())
    assert (out["health"], out["kind"], out["wear_percent"]) == ("ok", "nvme", 3)


def test_remapped_sectors_warn_and_name_the_count():
    assert health(ata([(5, "Reallocated_Sector_Ct", 8)])) == ("warn", ["8 sectors already remapped"])


def test_pending_or_uncorrectable_sectors_are_bad_because_data_was_unreadable():
    assert health(ata([(197, "Current_Pending_Sector", 3)]))[0] == "bad"
    assert health(ata([(198, "Offline_Uncorrectable", 1)]))[0] == "bad"


def test_cable_errors_warn():
    assert health(ata([(199, "UDMA_CRC_Error_Count", 12)])) == ("warn", ["12 cable errors"])


def test_a_drive_that_says_it_is_failing_is_bad_whatever_else_it_shows():
    assert health(ata(HEALTHY, passed=False))[0] == "bad"


def test_an_attribute_below_its_threshold_now_is_bad():
    raw = ata(HEALTHY)
    raw["ata_smart_attributes"]["table"][0]["when_failed"] = "FAILING_NOW"
    assert health(raw)[0] == "bad"


def test_the_count_is_the_low_32_bits_of_a_packed_raw_value():
    # some drives pack extra counters above the count that matters
    assert health(ata([(5, "Reallocated_Sector_Ct", (7 << 32) | 0)]))[0] == "ok"
    assert health(ata([(5, "Reallocated_Sector_Ct", (7 << 32) | 4)])) == ("warn", ["4 sectors already remapped"])


def test_heat_warns():
    assert health(ata(HEALTHY, temp=70)) == ("warn", ["running at 70°C"])


def test_nvme_critical_warning_media_errors_and_spent_spare_are_bad():
    assert health(nvme(critical_warning=4))[0] == "bad"
    assert health(nvme(media_errors=2)) == ("bad", ["2 media errors"])
    assert health(nvme(available_spare=8)) == ("bad", ["spare capacity is down to 8%"])


def test_nvme_wear_warns_at_90_and_is_bad_at_100():
    assert health(nvme(percentage_used=91)) == ("warn", ["91% of its rated wear used"])
    assert health(nvme(percentage_used=100)) == ("bad", ["its rated wear is used up"])


def test_a_sata_ssd_reads_wear_from_its_normalised_attribute():
    raw = ata(HEALTHY + [(177, "Wear_Leveling_Count", 0)], rotation=0)
    raw["ata_smart_attributes"]["table"][-1]["value"] = 7  # 7 left of 100
    out = smart.assess(raw)
    assert (out["kind"], out["wear_percent"]) == ("ssd", 93)
    assert out["health"] == "warn"


def test_a_spinning_disks_attribute_177_is_not_taken_for_wear():
    raw = ata(HEALTHY + [(177, "Whatever", 0)])
    raw["ata_smart_attributes"]["table"][-1]["value"] = 7
    assert smart.assess(raw)["wear_percent"] is None


def test_no_smart_status_is_unknown_not_ok():
    out = smart.assess({"device": {"name": "/dev/sdb"}, "model_name": "USB thing"})
    assert out["health"] == "unknown" and "no SMART data" in out["reasons"][0]


# ---- asleep, and the history of a drive ------------------------------------


def found(*disks, error=None):
    return {"disks": list(disks), "error": error}


@pytest.fixture(autouse=True)
def clean():
    smart._state.clear()
    yield
    smart._state.clear()


def test_a_drive_in_standby_keeps_its_last_reading_marked_asleep():
    smart.merge(found(ata([(5, "Reallocated_Sector_Ct", 8)])), 100.0)
    state = smart.merge(found({"device": {"name": "/dev/sda"}, "standby": True}), 200.0)
    (disk,) = state["disks"]
    assert disk["standby"] is True and disk["health"] == "warn" and disk["model"] == "ST1000DM010-2EP102"
    assert state["checked_at"] == 200.0


def test_a_drive_that_was_never_read_and_is_asleep_is_just_unknown():
    state = smart.merge(found({"device": {"name": "/dev/sda"}, "standby": True}), 1.0)
    assert state["disks"][0]["health"] == "unknown"


def test_a_drive_that_disappears_disappears():
    smart.merge(found(ata(HEALTHY), nvme()), 1.0)
    assert [d["device"] for d in smart.merge(found(nvme()), 2.0)["disks"]] == ["/dev/nvme0"]


def test_the_helpers_error_is_carried_so_the_page_can_say_why():
    assert smart.merge(found(error="smartctl isn't in this image: rebuild the agent"), 1.0)["error"].startswith("smartctl")


def test_snapshot_is_none_until_the_first_check():
    assert smart.snapshot() is None
    smart.merge(found(ata(HEALTHY)), 1.0)
    assert smart.snapshot()["disks"][0]["health"] == "ok"


# ---- the helper ------------------------------------------------------------


def fake_smartctl(monkeypatch, scan, per_device):
    monkeypatch.setattr(smart.shutil, "which", lambda name: "/usr/sbin/smartctl")

    def run(cmd, **kwargs):
        assert cmd[:2] == ["smartctl", "-j"]
        if cmd[2] == "--scan":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"devices": scan}))
        device = cmd[cmd.index("-n") + 2]
        assert cmd[cmd.index("-n") + 1] == "standby", "a SMART poll must never wake a sleeping drive"
        code, body = per_device[device]
        return SimpleNamespace(returncode=code, stdout=json.dumps(body) if body is not None else "Device is in STANDBY mode, exit(2)\n")

    monkeypatch.setattr(smart.subprocess, "run", run)


def test_collect_scans_then_reads_each_disk_with_its_own_type_and_trims_the_json(monkeypatch):
    fake_smartctl(monkeypatch, [{"name": "/dev/sda", "type": "sat"}, {"name": "/dev/nvme0", "type": "nvme"}],
                  {"/dev/sda": (0, {**ata(HEALTHY), "serial_number": "SECRET", "smartctl": {"exit_status": 0}}),
                   "/dev/nvme0": (0, nvme())})
    out = smart.collect()
    assert [d["device"]["name"] for d in out["disks"]] == ["/dev/sda", "/dev/nvme0"]
    assert all("serial_number" not in d and "smartctl" not in d for d in out["disks"])
    assert smart.assess(out["disks"][0])["health"] == "ok"


def test_collect_marks_a_sleeping_drive_by_the_exit_status_not_by_guessing(monkeypatch):
    fake_smartctl(monkeypatch, [{"name": "/dev/sda", "type": "sat"}, {"name": "/dev/sdb", "type": "sat"}],
                  {"/dev/sda": (2, None), "/dev/sdb": (1, None)})
    asleep, broken = smart.collect()["disks"]
    assert asleep["standby"] is True and not asleep["unreadable"]
    assert broken["unreadable"] is True and not broken["standby"]


def test_collect_without_smartctl_says_to_rebuild(monkeypatch):
    monkeypatch.setattr(smart.shutil, "which", lambda name: None)
    out = smart.collect()
    assert out["disks"] == [] and "rebuild" in out["error"]


class Helper:
    def __init__(self, output):
        self.output, self.removed = output, False

    def wait(self, timeout):
        return {"StatusCode": 0}

    def logs(self, **kw):
        assert kw == {"stdout": True, "stderr": False}  # a warning on stderr must not corrupt the JSON
        return self.output

    def remove(self, force):
        self.removed = True


class Client:
    def __init__(self, output):
        self.helper, self.ran = Helper(output), None
        self.containers = self

    def run(self, image, **kw):
        self.ran = (image, kw)
        return self.helper


def test_refresh_runs_a_fixed_privileged_helper_from_the_agents_image_and_cleans_up(monkeypatch):
    import rebuild
    monkeypatch.setattr(rebuild, "helper_image", lambda client: "homelab-agent")
    client = Client(json.dumps({"disks": [ata(HEALTHY)]}).encode())
    state = smart.refresh(client)
    image, kw = client.ran
    assert image == "homelab-agent" and kw["command"] == ["python", "smart.py", "collect"]
    assert kw["privileged"] is True and kw["network_mode"] == "none"
    assert client.helper.removed and state["disks"][0]["health"] == "ok"


def test_refresh_survives_a_helper_that_printed_nonsense(monkeypatch):
    import rebuild
    monkeypatch.setattr(rebuild, "helper_image", lambda client: "homelab-agent")
    state = smart.refresh(Client(b"Traceback (most recent call last)..."))
    assert state["disks"] == [] and "no readable answer" in state["error"]
