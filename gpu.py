"""AMD, Intel and other GPUs, read from sysfs.

``nvidia-smi`` covers NVIDIA. Everything else (and an NVIDIA card the
container has no runtime for) is found by walking ``/sys/class/drm``, which
Docker mounts into every container, so none of this needs configuration.

What each driver tells us, and no more than it tells us:

* **amdgpu**: load (``gpu_busy_percent``), VRAM or shared memory, core and
  memory clocks, temperatures (edge, junction, memory), power and its cap, fan.
* **i915 / xe** (Intel): clocks, and how much of the time the GPU was out of
  its idle state (RC6 / gt idle). That is *activity*, not engine load, so it
  is reported as ``active_percent`` and never as ``utilization_percent``.
  Discrete Arc cards add power, temperature and fan through hwmon.
* **anything else** (nouveau, old chips): hwmon temperature and fan if the
  driver has them. A card the kernel says nothing about is listed by name with
  a ``limited`` note saying so, rather than shown as a quiet GPU.

Rates (activity, power from an energy counter) need two samples; the first
call after start reports ``None`` for them and the next one has a value.
"""

from __future__ import annotations

import glob
import os
import re
import threading
import time
from pathlib import Path

DRM_ROOT = "/sys/class/drm"
# The agent mounts the host's filesystem at /host, so the host's own device
# names are usable; the container image has none.
PCI_IDS = (
    "/host/usr/share/hwdata/pci.ids",
    "/host/usr/share/misc/pci.ids",
    "/usr/share/hwdata/pci.ids",
    "/usr/share/misc/pci.ids",
)

VENDORS = {"0x10de": "nvidia", "0x1002": "amd", "0x8086": "intel"}
VENDOR_NAMES = {"nvidia": "NVIDIA", "amd": "AMD", "intel": "Intel"}

_lock = threading.Lock()
_last: dict[str, dict] = {}  # pci slot -> the previous sample's counters
_names: dict[tuple[str, str], str | None] = {}


def _read(path) -> str | None:
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _number(path, scale: float = 1.0) -> float | None:
    raw = _read(path)
    if raw is None:
        return None
    try:
        return float(raw.split()[0]) * scale
    except (ValueError, IndexError):
        return None


def _first(*values):
    return next((v for v in values if v is not None), None)


def pci_name(vendor_id: str, device_id: str) -> str | None:
    """The product name pci.ids gives this device, marketing name where it has one
    ("TU116 [GeForce GTX 1650 SUPER]" -> "GeForce GTX 1650 SUPER")."""
    key = (vendor_id.lower().removeprefix("0x"), device_id.lower().removeprefix("0x"))
    if key not in _names:
        _names[key] = _lookup(*key)
    return _names[key]


def _lookup(vendor: str, device: str) -> str | None:
    for path in PCI_IDS:
        try:
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            in_vendor = False
            for line in handle:
                if not line.strip() or line.startswith("#"):
                    continue
                if line[0] != "\t":
                    if in_vendor:
                        return None  # left the vendor's block without finding it
                    in_vendor = line[:4].lower() == vendor
                elif in_vendor and line[1] != "\t" and line[1:5].lower() == device:
                    name = line[5:].strip()
                    bracket = re.search(r"\[([^\]]+)\]\s*$", name)
                    return (bracket.group(1) if bracket else name) or None
        return None
    return None


def _hwmon(device: Path, now: float, previous: dict, sample: dict) -> dict:
    """Temperatures, power, fan and clocks from the card's hwmon directory."""
    out: dict = {}
    for hwmon in sorted(glob.glob(str(device / "hwmon" / "hwmon*"))):
        hwmon = Path(hwmon)
        temps = {}
        for index in range(1, 6):
            value = _number(hwmon / f"temp{index}_input", 0.001)
            if value is not None:
                temps[(_read(hwmon / f"temp{index}_label") or ("edge" if index == 1 else f"temp{index}")).lower()] = round(value, 1)
        if temps:
            out.setdefault("temperature_c", _first(temps.get("edge"), temps.get("temp1"), next(iter(temps.values()))))
            if "junction" in temps or "hotspot" in temps:
                out.setdefault("hotspot_temp_c", _first(temps.get("junction"), temps.get("hotspot")))
            if "mem" in temps:
                out.setdefault("memory_temp_c", temps["mem"])

        power = _first(_number(hwmon / "power1_average", 1e-6), _number(hwmon / "power1_input", 1e-6))
        energy = _number(hwmon / "energy1_input")  # microjoules, only ever grows
        if power is None and energy is not None:
            sample["energy_uj"] = energy
            if previous.get("energy_uj") is not None and now > previous["t"] and energy >= previous["energy_uj"]:
                power = (energy - previous["energy_uj"]) / (now - previous["t"]) / 1e6
        if power is not None:
            out.setdefault("power_draw_w", round(power, 1))
        cap = _first(_number(hwmon / "power1_cap", 1e-6), _number(hwmon / "power1_max", 1e-6))
        if cap:
            out.setdefault("power_limit_w", round(cap, 1))

        rpm = _number(hwmon / "fan1_input")
        if rpm is not None:
            out.setdefault("fan_rpm", round(rpm))
        pwm, pwm_max = _number(hwmon / "pwm1"), _number(hwmon / "pwm1_max") or 255.0
        fan_max = _number(hwmon / "fan1_max")
        if pwm is not None:
            out.setdefault("fan_percent", round(min(100.0, pwm / pwm_max * 100), 1))
        elif rpm is not None and fan_max:
            out.setdefault("fan_percent", round(min(100.0, rpm / fan_max * 100), 1))

        core, mem = _number(hwmon / "freq1_input", 1e-6), _number(hwmon / "freq2_input", 1e-6)
        if core is not None:
            out.setdefault("core_clock_mhz", round(core))
        if mem is not None:
            out.setdefault("memory_clock_mhz", round(mem))
    return out


def _amd(device: Path) -> dict:
    out: dict = {}
    busy = _number(device / "gpu_busy_percent")
    if busy is not None:
        out["utilization_percent"] = round(busy, 1)
    total, used = _number(device / "mem_info_vram_total"), _number(device / "mem_info_vram_used")
    if total:
        mb = 1024 * 1024
        out["memory_total_mb"], out["memory_used_mb"] = round(total / mb), round((used or 0) / mb)
    name = _read(device / "product_name")
    if name:
        out["product_name"] = name
    # amdgpu reports the clocks it is running at through hwmon on most boards; older
    # ones only have the DPM tables, where the active level is the line marked "*".
    for key, table in (("core_clock_mhz", "pp_dpm_sclk"), ("memory_clock_mhz", "pp_dpm_mclk")):
        clock = _clock_from_dpm(device / table)
        if clock is not None:
            out[key] = round(clock)
    return out


def _clock_from_dpm(path: Path) -> float | None:
    """The line marked ``*`` in a pp_dpm_* table: ``1: 1400Mhz *``."""
    text = _read(path)
    for line in (text or "").splitlines():
        match = re.search(r"(\d+(?:\.\d+)?)\s*[Mm][Hh][Zz]\s*\*", line)
        if match:
            return float(match.group(1))
    return None


def _intel(card: Path, device: Path, now: float, previous: dict, sample: dict) -> dict:
    out: dict = {}
    gt0 = card / "gt" / "gt0"
    xe = device / "tile0" / "gt0"
    clock = _first(
        _number(card / "gt_act_freq_mhz"), _number(gt0 / "rps_act_freq_mhz"), _number(xe / "freq0" / "act_freq"),
        _number(card / "gt_cur_freq_mhz"), _number(gt0 / "rps_cur_freq_mhz"), _number(xe / "freq0" / "cur_freq"),
    )
    if clock is not None:
        out["core_clock_mhz"] = round(clock)
    top = _first(_number(card / "gt_max_freq_mhz"), _number(gt0 / "rps_max_freq_mhz"), _number(xe / "freq0" / "max_freq"))
    if top is not None:
        out["core_clock_max_mhz"] = round(top)

    # Time spent in the idle state (RC6 on i915, gt-c6 on xe), in ms since boot.
    idle = _first(_number(gt0 / "rc6_residency_ms"), _number(card / "power" / "rc6_residency_ms"),
                  _number(xe / "gtidle" / "idle_residency_ms"))
    if idle is not None:
        sample["idle_ms"] = idle
        if previous.get("idle_ms") is not None and now > previous["t"] and idle >= previous["idle_ms"]:
            asleep = (idle - previous["idle_ms"]) / ((now - previous["t"]) * 1000)
            out["active_percent"] = round(max(0.0, min(1.0, 1 - asleep)) * 100, 1)

    lmem_total, lmem_free = _number(card / "lmem_total_bytes"), _number(card / "lmem_avail_bytes")
    if lmem_total:
        mb = 1024 * 1024
        out["memory_total_mb"], out["memory_used_mb"] = round(lmem_total / mb), round((lmem_total - (lmem_free or 0)) / mb)
    return out


def _card(card: Path, now: float) -> dict | None:
    device = card / "device"
    vendor_id = (_read(device / "vendor") or "").lower()
    if not vendor_id:
        return None
    device_id = (_read(device / "device") or "").lower()
    vendor = VENDORS.get(vendor_id, "unknown")
    slot = os.path.basename(os.path.realpath(device)) or card.name
    try:
        driver = os.path.basename(os.readlink(device / "driver"))
    except OSError:
        driver = None

    with _lock:
        previous = _last.get(slot, {})
        sample: dict = {"t": now}
        details = _hwmon(device, now, previous, sample)
        if vendor == "amd":
            specific = _amd(device)
        elif vendor == "intel":
            specific = _intel(card, device, now, previous, sample)
        else:
            specific = {}
        for key, value in specific.items():
            details.setdefault(key, value)  # hwmon's clocks beat the DPM table's
        _last[slot] = sample

    prefix = VENDOR_NAMES.get(vendor, "")
    product = details.pop("product_name", None) or pci_name(vendor_id, device_id)
    pci_id = f"{vendor_id.removeprefix('0x')}:{device_id.removeprefix('0x')}".upper()
    if product:
        name = product if not prefix or product.lower().startswith(prefix.lower()) else f"{prefix} {product}"
    else:
        name = f"{vendor.upper()} GPU {pci_id}"  # the form the dashboard already splits the PCI id off

    gpu = {
        "vendor": vendor,
        "name": name,
        "device_id": device_id,
        "pci_id": pci_id,
        "pci_slot": slot,
        "driver": driver,
        "utilization_percent": None,
        "memory_used_mb": None,
        "memory_total_mb": None,
        "temperature_c": None,
        "power_draw_w": None,
        "power_limit_w": None,
        "fan_percent": None,
        **details,
    }
    measured = ("utilization_percent", "active_percent", "memory_total_mb", "temperature_c", "power_draw_w", "core_clock_mhz", "fan_percent")
    if vendor != "nvidia" and not any(gpu.get(key) is not None for key in measured):
        # Not a quiet GPU: one the kernel gives us nothing about (yet). The first
        # call has no rate to show, so don't claim "nothing" until a second one agrees.
        if previous:
            gpu["limited"] = (
                f"The {driver or 'kernel'} driver doesn't report load, clocks or temperature for this GPU."
            )
    return gpu


def get_drm_gpu_stats() -> list[dict] | None:
    now = time.monotonic()
    gpus = []
    for path in sorted(glob.glob(f"{DRM_ROOT}/card*")):
        card = Path(path)
        # card0, card1... not the connector entries (card0-HDMI-A-1).
        if not card.name.removeprefix("card").isdigit() or not (card / "device").exists():
            continue
        gpu = _card(card, now)
        if gpu:
            gpus.append(gpu)
    return gpus or None
