"""AMD, Intel and other GPUs read from a sysfs tree. Each test builds the files a
real driver exposes (named as in the kernel's documentation) in a temp directory
and points the reader at it."""

import os

import pytest

import gpu


@pytest.fixture(autouse=True)
def fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(gpu, "DRM_ROOT", str(tmp_path / "drm"))
    monkeypatch.setattr(gpu, "PCI_IDS", (str(tmp_path / "pci.ids"),))
    gpu._last.clear()
    gpu._names.clear()
    return tmp_path


def card(root, n, vendor, device, driver, files=None, hwmon=None, slot="0000:01:00.0", cardfiles=None):
    """card<n> -> a PCI device directory, like /sys/class/drm/card<n>."""
    pci = root / "pci" / slot
    pci.mkdir(parents=True, exist_ok=True)
    (pci / "vendor").write_text(vendor + "\n")
    (pci / "device").write_text(device + "\n")
    drivers = root / "drivers"
    drivers.mkdir(exist_ok=True)
    (drivers / driver).mkdir(exist_ok=True)
    if not (pci / "driver").exists():
        os.symlink(drivers / driver, pci / "driver")
    for name, value in (files or {}).items():
        target = pci / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(value) + "\n")
    if hwmon:
        directory = pci / "hwmon" / "hwmon3"
        directory.mkdir(parents=True)
        for name, value in hwmon.items():
            (directory / name).write_text(str(value) + "\n")
    drm = root / "drm"
    drm.mkdir(exist_ok=True)
    cd = drm / f"card{n}"
    cd.mkdir()
    os.symlink(pci, cd / "device")
    (drm / f"card{n}-HDMI-A-1").mkdir()  # a connector entry, which must be ignored
    for name, value in (cardfiles or {}).items():
        target = cd / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(value) + "\n")
    return pci


MB = 1024 * 1024
AMD_FILES = {"gpu_busy_percent": 37, "mem_info_vram_total": 8192 * MB, "mem_info_vram_used": 2048 * MB}
AMD_HWMON = {
    "temp1_input": 52000, "temp1_label": "edge", "temp2_input": 61000, "temp2_label": "junction",
    "temp3_input": 58000, "temp3_label": "mem", "power1_average": 95_000_000, "power1_cap": 132_000_000,
    "fan1_input": 1450, "fan1_max": 3200, "pwm1": 102, "pwm1_max": 255, "freq1_input": 2_100_000_000,
    "freq2_input": 1_750_000_000,
}


# ---- AMD -----------------------------------------------------------------


def test_an_amd_card_reports_load_vram_clocks_power_and_fan(fresh):
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", AMD_FILES, AMD_HWMON)
    (gpus,) = [gpu.get_drm_gpu_stats()]
    (g,) = gpus
    assert g["vendor"] == "amd" and g["driver"] == "amdgpu" and g["pci_id"] == "1002:73FF"
    assert g["utilization_percent"] == 37.0
    assert (g["memory_used_mb"], g["memory_total_mb"]) == (2048, 8192)
    assert g["temperature_c"] == 52.0  # the edge, not the hotter junction that would trip the alert
    assert (g["hotspot_temp_c"], g["memory_temp_c"]) == (61.0, 58.0)
    assert (g["power_draw_w"], g["power_limit_w"]) == (95.0, 132.0)
    assert g["fan_percent"] == 40.0 and g["fan_rpm"] == 1450  # 102 of 255
    assert (g["core_clock_mhz"], g["memory_clock_mhz"]) == (2100, 1750)
    assert "limited" not in g


def test_amd_without_hwmon_clocks_falls_back_to_the_dpm_table(fresh):
    files = {**AMD_FILES, "pp_dpm_sclk": "0: 300Mhz\n1: 1400Mhz *\n2: 2000Mhz\n", "pp_dpm_mclk": "0: 96Mhz\n1: 1000Mhz *\n"}
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", files, {"temp1_input": 40000})
    (g,) = gpu.get_drm_gpu_stats()
    assert (g["core_clock_mhz"], g["memory_clock_mhz"]) == (1400, 1000)


def test_fan_percent_falls_back_to_rpm_over_max(fresh):
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", AMD_FILES, {"fan1_input": 800, "fan1_max": 3200})
    (g,) = gpu.get_drm_gpu_stats()
    assert g["fan_percent"] == 25.0


def test_power1_input_is_used_when_there_is_no_average(fresh):
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", AMD_FILES, {"power1_input": 30_500_000})
    (g,) = gpu.get_drm_gpu_stats()
    assert g["power_draw_w"] == 30.5


# ---- Intel ---------------------------------------------------------------


def test_intel_activity_is_one_minus_the_idle_share_between_two_samples(fresh, monkeypatch):
    card(fresh, 0, "0x8086", "0x9a49", "i915", slot="0000:00:02.0",
               cardfiles={"gt_act_freq_mhz": 450, "gt_max_freq_mhz": 1300, "gt/gt0/rc6_residency_ms": 1000})
    clock = iter([100.0, 102.0])
    monkeypatch.setattr(gpu.time, "monotonic", lambda: next(clock))
    (first,) = gpu.get_drm_gpu_stats()
    assert "active_percent" not in first  # one sample is not a rate
    (fresh / "drm" / "card0" / "gt" / "gt0" / "rc6_residency_ms").write_text("2500\n")  # 1.5 s asleep of 2 s
    (second,) = gpu.get_drm_gpu_stats()
    assert second["active_percent"] == 25.0
    assert second["utilization_percent"] is None  # activity is not engine load
    assert (second["core_clock_mhz"], second["core_clock_max_mhz"]) == (450, 1300)
    assert second["pci_slot"] == "0000:00:02.0"


def test_intel_activity_never_goes_outside_zero_to_a_hundred(fresh, monkeypatch):
    card(fresh, 0, "0x8086", "0x9a49", "i915", cardfiles={"gt/gt0/rc6_residency_ms": 0, "gt_cur_freq_mhz": 300})
    clock = iter([10.0, 11.0])
    monkeypatch.setattr(gpu.time, "monotonic", lambda: next(clock))
    gpu.get_drm_gpu_stats()
    (fresh / "drm" / "card0" / "gt" / "gt0" / "rc6_residency_ms").write_text("5000\n")  # more idle than elapsed
    (g,) = gpu.get_drm_gpu_stats()
    assert g["active_percent"] == 0.0


def test_the_older_rc6_path_and_the_xe_driver_paths_are_read(fresh, monkeypatch):
    card(fresh, 0, "0x8086", "0x0166", "i915", cardfiles={"power/rc6_residency_ms": 0, "gt_cur_freq_mhz": 350})
    card(fresh, 1, "0x8086", "0xe20b", "xe", slot="0000:03:00.0", files={
        "tile0/gt0/freq0/act_freq": 2400, "tile0/gt0/freq0/max_freq": 2850, "tile0/gt0/gtidle/idle_residency_ms": 0})
    clock = iter([1.0, 2.0])  # one reading of the clock per scan, however many cards
    monkeypatch.setattr(gpu.time, "monotonic", lambda: next(clock))
    gpu.get_drm_gpu_stats()
    for path in ((fresh / "drm" / "card0" / "power" / "rc6_residency_ms"),
                 (fresh / "pci" / "0000:03:00.0" / "tile0" / "gt0" / "gtidle" / "idle_residency_ms")):
        path.write_text("500\n")
    old, new = gpu.get_drm_gpu_stats()
    assert old["active_percent"] == 50.0 and old["core_clock_mhz"] == 350
    assert new["active_percent"] == 50.0 and new["core_clock_mhz"] == 2400 and new["core_clock_max_mhz"] == 2850


def test_an_arc_card_adds_power_from_its_energy_counter_and_vram(fresh, monkeypatch):
    card(fresh, 0, "0x8086", "0x56a0", "i915", hwmon={"energy1_input": 10_000_000, "power1_max": 190_000_000, "temp1_input": 47000},
         cardfiles={"lmem_total_bytes": 16384 * MB, "lmem_avail_bytes": 14336 * MB, "gt_act_freq_mhz": 2100})
    clock = iter([5.0, 7.0])
    monkeypatch.setattr(gpu.time, "monotonic", lambda: next(clock))
    (first,) = gpu.get_drm_gpu_stats()
    assert first["power_draw_w"] is None and first["power_limit_w"] == 190.0
    (fresh / "pci" / "0000:01:00.0" / "hwmon" / "hwmon3" / "energy1_input").write_text("70000000\n")  # 60 J in 2 s
    (g,) = gpu.get_drm_gpu_stats()
    assert g["power_draw_w"] == 30.0 and g["temperature_c"] == 47.0
    assert (g["memory_used_mb"], g["memory_total_mb"]) == (2048, 16384)


def test_an_energy_counter_that_went_backwards_is_not_a_negative_wattage(fresh, monkeypatch):
    card(fresh, 0, "0x8086", "0x56a0", "i915", hwmon={"energy1_input": 90_000_000})
    clock = iter([1.0, 2.0])
    monkeypatch.setattr(gpu.time, "monotonic", lambda: next(clock))
    gpu.get_drm_gpu_stats()
    (fresh / "pci" / "0000:01:00.0" / "hwmon" / "hwmon3" / "energy1_input").write_text("1000\n")
    (g,) = gpu.get_drm_gpu_stats()
    assert g["power_draw_w"] is None


# ---- a driver that says nothing ------------------------------------------


def test_a_card_the_kernel_says_nothing_about_is_called_limited_not_quiet(fresh):
    card(fresh, 0, "0x8086", "0x0046", "i915", slot="0000:00:02.0")
    (first,) = gpu.get_drm_gpu_stats()
    assert "limited" not in first  # one look is not enough to say so
    (second,) = gpu.get_drm_gpu_stats()
    assert "i915" in second["limited"] and second["utilization_percent"] is None


def test_an_nvidia_card_the_container_cannot_query_is_left_to_the_runtime_hint(fresh):
    card(fresh, 0, "0x10de", "0x2187", "nvidia")
    gpu.get_drm_gpu_stats()
    (g,) = gpu.get_drm_gpu_stats()
    assert g["vendor"] == "nvidia" and "limited" not in g


# ---- names and the card list ---------------------------------------------

PCI_IDS = """\
# a comment
1002  Advanced Micro Devices, Inc. [AMD/ATI]
\t73ff  Navi 23 [Radeon RX 6600/6600 XT/6600M]
\t\t1043 0510  subsystem line that must not match
8086  Intel Corporation
\t0046  Core Processor Integrated Graphics Controller
\t9a49  TigerLake-LP GT2 [Iris Xe Graphics]
10de  NVIDIA Corporation
\t2187  TU116 [GeForce GTX 1650 SUPER]
C 03  Display controller
\t00  VGA compatible controller
"""


def test_names_come_from_pci_ids_with_the_marketing_name_and_a_vendor(fresh):
    (fresh / "pci.ids").write_text(PCI_IDS)
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", AMD_FILES)
    card(fresh, 1, "0x8086", "0x9a49", "i915", slot="0000:00:02.0")
    card(fresh, 2, "0x8086", "0x0046", "i915", slot="0000:00:03.0")
    card(fresh, 3, "0x10de", "0x2187", "nvidia", slot="0000:02:00.0")
    names = [g["name"] for g in gpu.get_drm_gpu_stats()]
    assert names == ["AMD Radeon RX 6600/6600 XT/6600M", "Intel Iris Xe Graphics",
                     "Intel Core Processor Integrated Graphics Controller", "NVIDIA GeForce GTX 1650 SUPER"]


def test_without_pci_ids_the_old_name_with_the_id_is_kept(fresh):
    card(fresh, 0, "0x1002", "0x1636", "amdgpu", AMD_FILES)
    (g,) = gpu.get_drm_gpu_stats()
    assert g["name"] == "AMD GPU 1002:1636"


def test_an_unknown_device_is_not_found_in_a_vendors_block_that_ends(fresh):
    (fresh / "pci.ids").write_text(PCI_IDS)
    assert gpu.pci_name("0x8086", "0xffff") is None
    assert gpu.pci_name("0x9999", "0x0001") is None


def test_amds_own_product_name_wins_over_pci_ids(fresh):
    (fresh / "pci.ids").write_text(PCI_IDS)
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", {**AMD_FILES, "product_name": "Radeon PRO W6600"})
    (g,) = gpu.get_drm_gpu_stats()
    assert g["name"] == "AMD Radeon PRO W6600"


def test_connectors_and_cards_without_a_device_are_skipped(fresh):
    (fresh / "drm").mkdir()
    (fresh / "drm" / "card9").mkdir()  # no device link
    assert gpu.get_drm_gpu_stats() is None


def test_two_cards_are_told_apart_by_pci_slot(fresh):
    card(fresh, 0, "0x1002", "0x73ff", "amdgpu", AMD_FILES, slot="0000:03:00.0")
    card(fresh, 1, "0x1002", "0x73ff", "amdgpu", {**AMD_FILES, "gpu_busy_percent": 90}, slot="0000:06:00.0")
    a, b = gpu.get_drm_gpu_stats()
    assert (a["pci_slot"], b["pci_slot"]) == ("0000:03:00.0", "0000:06:00.0")
    assert (a["utilization_percent"], b["utilization_percent"]) == (37.0, 90.0)
