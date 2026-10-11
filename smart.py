"""Disk health from SMART, with nothing installed on the host.

smartctl lives in this agent's own image. Disks are not visible from an
ordinary container, so every ``SMART_INTERVAL_MINUTES`` (default 30, 0 = off)
the agent starts a short-lived privileged helper from that same image, which
runs ``python smart.py collect`` and exits. The helper's command is fixed: no
request ever chooses what runs in it.

A drive that is spun down is left alone (``smartctl -n standby``): asking
would wake it, and a SMART poll that keeps a backup disk spinning all night is
worse than a stale reading. It keeps its last reading, marked ``standby``.

``assess`` is the judgement, kept separate so it is testable without a disk:

* **bad**: the drive says it is failing; pending or uncorrectable sectors (the
  drive could not read data it should have); an NVMe critical warning,
  exhausted spare, or media errors; a wear-out of 100%.
* **warn**: reallocated sectors (it has already remapped some), CRC errors
  (usually the cable), wear over 90%, a hot drive.
* **ok**: none of that. **unknown**: no SMART data came back at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time

from log import log


def _minutes() -> float:
    try:
        return float(os.getenv("SMART_INTERVAL_MINUTES") or 30)
    except ValueError:
        return 30.0


INTERVAL_MINUTES = _minutes()
HELPER_TIMEOUT = 180
HOT_C = 65

_state: dict = {}
_lock = threading.Lock()

# ---- inside the helper ------------------------------------------------------

KEEP = ("device", "model_name", "firmware_version", "user_capacity", "rotation_rate", "smart_status",
        "temperature", "power_on_time", "power_cycle_count", "ata_smart_attributes", "nvme_smart_health_information_log")


def _smartctl(args: list[str]) -> tuple[int, dict | None]:
    run = subprocess.run(["smartctl", "-j", *args], capture_output=True, text=True, timeout=60)
    try:
        return run.returncode, json.loads(run.stdout)
    except ValueError:
        return run.returncode, None


def collect() -> dict:
    """Every disk smartctl can see, trimmed to what ``assess`` reads."""
    if not shutil.which("smartctl"):
        return {"error": "smartctl isn't in this image: rebuild the agent", "disks": []}
    _, scan = _smartctl(["--scan"])
    disks = []
    for entry in ((scan or {}).get("devices") or []):
        name = entry.get("name")
        if not name:
            continue
        args = ["-a", "-n", "standby", name] + (["-d", entry["type"]] if entry.get("type") else [])
        code, data = _smartctl(args)
        if data is None:
            # No JSON is what a drive in standby gives (exit status 2).
            disks.append({"device": {"name": name}, "standby": code == 2, "unreadable": code != 2})
            continue
        disks.append({key: data[key] for key in KEEP if key in data} | {"device": {**(data.get("device") or {}), "name": name}})
    return {"disks": disks}


# ---- the judgement ----------------------------------------------------------


def _attributes(raw: dict) -> dict[int, dict]:
    table = ((raw.get("ata_smart_attributes") or {}).get("table")) or []
    return {a["id"]: a for a in table if isinstance(a, dict) and "id" in a}


def _raw(attributes: dict, attribute_id: int) -> int | None:
    entry = attributes.get(attribute_id)
    value = ((entry or {}).get("raw") or {}).get("value")
    # The raw value of some attributes packs several counters into one number; the
    # low 32 bits are the count that matters for the ones used here.
    return int(value) & 0xFFFFFFFF if isinstance(value, int) else None


def assess(raw: dict) -> dict:
    device = raw.get("device") or {}
    name = device.get("name") or "?"
    out = {"device": name, "model": raw.get("model_name"), "kind": None, "size_gb": None, "health": "unknown",
           "reasons": [], "temperature_c": None, "power_on_hours": None, "wear_percent": None, "standby": bool(raw.get("standby"))}
    if raw.get("standby") or raw.get("unreadable") or "smart_status" not in raw:
        out["reasons"] = ["asleep: showing its last reading"] if raw.get("standby") else ["no SMART data (a USB bridge or virtual disk often has none)"]
        return out

    nvme = raw.get("nvme_smart_health_information_log")
    attrs = _attributes(raw)
    spins = (raw.get("rotation_rate") or 0) > 0
    out["kind"] = "nvme" if nvme is not None or device.get("protocol") == "NVMe" else "hdd" if spins else "ssd"
    capacity = (raw.get("user_capacity") or {}).get("bytes")
    out["size_gb"] = round(capacity / 1e9) if capacity else None
    out["temperature_c"] = (raw.get("temperature") or {}).get("current", (nvme or {}).get("temperature"))
    out["power_on_hours"] = (raw.get("power_on_time") or {}).get("hours", (nvme or {}).get("power_on_hours"))

    bad: list[str] = []
    warn: list[str] = []
    if (raw.get("smart_status") or {}).get("passed") is False:
        bad.append("the drive reports that it is failing")

    if nvme is not None:
        if nvme.get("critical_warning"):
            bad.append("the drive has raised a critical warning")
        spare, floor = nvme.get("available_spare"), nvme.get("available_spare_threshold")
        if isinstance(spare, int) and isinstance(floor, int) and spare <= floor:
            bad.append(f"spare capacity is down to {spare}%")
        if nvme.get("media_errors"):
            bad.append(f"{nvme['media_errors']} media errors")
        used = nvme.get("percentage_used")
        if isinstance(used, int):
            out["wear_percent"] = used
    else:
        pending, uncorrectable, reallocated, crc = _raw(attrs, 197), _raw(attrs, 198), _raw(attrs, 5), _raw(attrs, 199)
        if pending:
            bad.append(f"{pending} sectors waiting to be remapped (unreadable now)")
        if uncorrectable:
            bad.append(f"{uncorrectable} sectors it could not correct")
        if reallocated:
            warn.append(f"{reallocated} sectors already remapped")
        if crc:
            warn.append(f"{crc} cable errors")
        for attribute_id in (177, 233, 231):  # wear levelling, media wearout, life left: 100 is new
            entry = attrs.get(attribute_id)
            if entry and isinstance(entry.get("value"), int) and not spins:
                out["wear_percent"] = max(0, 100 - entry["value"])
                break
        for entry in attrs.values():
            if entry.get("when_failed") == "FAILING_NOW":
                bad.append(f"{entry.get('name', 'an attribute')} is below its failure threshold")

    wear = out["wear_percent"]
    if wear is not None and wear >= 100:
        bad.append("its rated wear is used up")
    elif wear is not None and wear >= 90:
        warn.append(f"{wear}% of its rated wear used")
    if isinstance(out["temperature_c"], (int, float)) and out["temperature_c"] >= HOT_C:
        warn.append(f"running at {out['temperature_c']}°C")

    out["reasons"] = bad + warn
    out["health"] = "bad" if bad else "warn" if warn else "ok"
    return out


# ---- in the agent -----------------------------------------------------------


def refresh(client) -> dict:
    """Run the helper, judge what it found, remember it."""
    import rebuild  # not at the top: the helper itself runs this file and needs neither
    import terminal

    container = client.containers.run(
        rebuild.helper_image(client),
        command=["python", "smart.py", "collect"],
        detach=True, privileged=True, network_mode="none",
        labels={terminal.HELPER_LABEL: "smart"},
    )
    try:
        container.wait(timeout=HELPER_TIMEOUT)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
    try:
        found = json.loads(output)
    except ValueError:
        found = {"error": "the SMART helper gave no readable answer", "disks": []}
    return merge(found, time.time())


def merge(found: dict, now: float) -> dict:
    """A drive that is asleep keeps what it said last time."""
    with _lock:
        before = {d["device"]: d for d in _state.get("disks", [])}
        disks = []
        for raw in found.get("disks") or []:
            item = assess(raw)
            old = before.get(item["device"])
            if item["standby"] and old and old["health"] != "unknown":
                item = {**old, "standby": True}
            disks.append(item)
        _state.clear()
        _state.update({"disks": disks, "checked_at": now, "error": found.get("error")})
        return dict(_state)


def snapshot() -> dict | None:
    with _lock:
        return dict(_state) if _state else None


def loop(client) -> None:
    time.sleep(20)  # let the agent finish starting
    while INTERVAL_MINUTES > 0:
        try:
            refresh(client)
        except Exception as error:  # noqa: BLE001
            log.warning("disk health check failed: %s", error)
        time.sleep(INTERVAL_MINUTES * 60)


def start_loop(client) -> None:
    if INTERVAL_MINUTES > 0:
        threading.Thread(target=loop, args=(client,), daemon=True).start()


if __name__ == "__main__":
    if sys.argv[1:] == ["collect"]:
        print(json.dumps(collect()))
    else:
        sys.exit("usage: smart.py collect")
