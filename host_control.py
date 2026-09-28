"""The machine itself: systemd services, OS package updates, reboot and
power off.

The agent runs in a container and can't touch the host's init, so each
command runs through the same privileged helper as a host shell
(``nsenter -t 1 -a``). That is root on the machine, which is why this is
behind the same switch as host shells, ``TERMINAL_ENABLED``.

**Anything long or disruptive runs as a transient systemd unit on the host**
(``systemd-run``), not inside the helper. An OS upgrade that includes
Docker restarts the Docker daemon, which kills every container — a helper
running ``apt-get`` would die mid-dpkg and leave the package database
broken. A systemd unit doesn't care what Docker does. The same goes for a
reboot, which is scheduled a few seconds out so the request can answer
first.

Facts (failed services, pending updates, reboot needed) are gathered in
the background every ``FACTS_MINUTES`` and ride the ``/containers``
snapshot, so the dashboard can show them — and alert on them — without
asking.
"""

from __future__ import annotations

import re
import shlex
import threading
import time

import rebuild
import terminal
from log import audit, log

FACTS_MINUTES = 15
APT_UPDATE_HOURS = 24
HELPER_TIMEOUT = 120
UPGRADE_UNIT = "homelab-os-upgrade"
UPGRADE_LOG = "/var/log/homelab-os-upgrade.log"

UNIT = re.compile(r"^[\w@.:\\-]+\.service$")  # systemd escapes use backslashes: \x2d
# Stopping these cuts the machine off from the dashboard (or from you).
NO_STOP = {"docker.service", "containerd.service", "tailscaled.service",
           "ssh.service", "sshd.service", "systemd-networkd.service", "NetworkManager.service"}

_facts: dict = {}
_lock = threading.Lock()
_last_apt_update = 0.0


class HostError(Exception):
    """Shown to the user as-is."""


def enabled() -> bool:
    return terminal.enabled()


def run(client, script: str, *, timeout: int = HELPER_TIMEOUT) -> tuple[int, str]:
    """Run a shell script on the host (as root, in its namespaces)."""
    container = client.containers.run(
        rebuild.helper_image(client),
        command=["nsenter", "-t", "1", "-a", "--", "sh", "-c", script],
        detach=True, privileged=True, pid_mode="host", network_mode="host",
        labels={terminal.HELPER_LABEL: "host-control"},
    )
    try:
        result = container.wait(timeout=timeout)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        return code, container.logs().decode("utf-8", "replace")
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


def _require():
    if not enabled():
        raise HostError("host control is off here — turn on 'Allow terminals and host control'")


# --- facts -------------------------------------------------------------------

FACTS_SCRIPT = r"""
echo "failed:$(systemctl list-units --type=service --state=failed --plain --no-legend --no-pager | awk '{print $1}' | tr '\n' ' ')"
[ -f /var/run/reboot-required ] && echo "reboot:1" || echo "reboot:0"
if command -v apt-get >/dev/null 2>&1; then
  echo "pkg:apt"
  echo "updates:$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  echo "security:$(apt list --upgradable 2>/dev/null | grep -c -- '-security')"
else
  echo "pkg:none"
fi
echo "upgrading:$(systemctl is-active homelab-os-upgrade 2>/dev/null)"
"""


def parse_facts(output: str) -> dict:
    values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
    pkg = values.get("pkg", "none").strip()
    return {
        "failed_units": values.get("failed", "").split(),
        "reboot_required": values.get("reboot", "0").strip() == "1",
        "package_manager": None if pkg == "none" else pkg,
        "os_updates": int(values["updates"]) if values.get("updates", "").strip().isdigit() else None,
        "security_updates": int(values["security"]) if values.get("security", "").strip().isdigit() else None,
        "upgrading": values.get("upgrading", "").strip() in ("active", "activating"),
        "checked_at": time.time(),
    }


def refresh_facts(client, *, apt_update: bool = False) -> dict:
    script = ("apt-get update -qq >/dev/null 2>&1; " if apt_update else "") + FACTS_SCRIPT
    code, output = run(client, script, timeout=600 if apt_update else HELPER_TIMEOUT)
    facts = parse_facts(output)
    with _lock:
        _facts.clear()
        _facts.update(facts)
    return dict(facts)


def facts() -> dict | None:
    with _lock:
        return dict(_facts) if _facts else None


def loop(client) -> None:
    global _last_apt_update
    while True:
        if enabled():
            try:
                due = time.time() - _last_apt_update >= APT_UPDATE_HOURS * 3600
                refresh_facts(client, apt_update=due)
                if due:
                    _last_apt_update = time.time()
            except Exception as error:  # noqa: BLE001
                log.debug("host facts failed: %s", error)
        time.sleep(FACTS_MINUTES * 60)


def start_loop(client) -> None:
    threading.Thread(target=loop, args=(client,), daemon=True).start()


# --- services --------------------------------------------------------------------

def services(client) -> list[dict]:
    _require()
    code, output = run(client, "systemctl list-units --type=service --all --plain --no-legend --no-pager")
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            rows.append({
                "unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
                "protected": parts[0] in NO_STOP,
            })
    rows.sort(key=lambda r: (r["active"] != "failed", r["active"] != "active", r["unit"]))
    return rows


def _unit(name: str) -> str:
    if not UNIT.match(name or ""):
        raise HostError(f"{name!r} isn't a service name")
    return name


def service_action(client, unit: str, action: str) -> dict:
    _require()
    unit = _unit(unit)
    if action not in ("start", "stop", "restart"):
        raise HostError("action must be start, stop or restart")
    if action == "stop" and unit in NO_STOP:
        raise HostError(f"stopping {unit} would cut this machine off — restart it instead")
    q = shlex.quote(unit)
    code, output = run(client, f"systemctl {action} {q} 2>&1; systemctl is-active {q}")
    audit.info("host: %s %s -> %s", action, unit, output.strip().splitlines()[-1:] or "?")
    state = (output.strip().splitlines() or ["unknown"])[-1]
    return {"unit": unit, "action": action, "active": state, "ok": code == 0 or state == "active",
            "output": output[-2000:]}


def service_logs(client, unit: str, lines: int = 200) -> str:
    _require()
    unit = _unit(unit)
    lines = max(10, min(int(lines), 2000))
    code, output = run(client, f"journalctl -u {shlex.quote(unit)} -n {lines} --no-pager -o short-iso")
    return output


# --- OS updates -------------------------------------------------------------------

def os_updates(client) -> dict:
    """Refresh the package lists and say what would be upgraded."""
    _require()
    code, output = run(
        client,
        "command -v apt-get >/dev/null || { echo NOAPT; exit 0; }; "
        "apt-get update -qq >/dev/null 2>&1; apt list --upgradable 2>/dev/null | tail -n +2",
        timeout=600,
    )
    if "NOAPT" in output:
        raise HostError("only apt (Debian/Ubuntu) hosts can be updated from here")
    packages = []
    for line in output.splitlines():
        m = re.match(r"^([^/]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            packages.append({"name": m[1], "suite": m[2], "version": m[3], "from": m[4],
                             "security": "-security" in m[2]})
    refresh_facts(client)
    return {"packages": packages}


def start_upgrade(client) -> dict:
    """``apt-get upgrade`` as a transient systemd unit — see the module
    docstring for why not in the helper."""
    _require()
    current = facts() or {}
    if current.get("upgrading"):
        raise HostError("an upgrade is already running")
    script = (
        f"systemd-run --unit={UPGRADE_UNIT} --collect --quiet "
        "--setenv=DEBIAN_FRONTEND=noninteractive sh -c "
        f"'apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade "
        f"> {UPGRADE_LOG} 2>&1; echo \"exit: $?\" >> {UPGRADE_LOG}'"
    )
    code, output = run(client, f"rm -f {UPGRADE_LOG}; {script} && echo started")
    if "started" not in output:
        raise HostError(f"couldn't start the upgrade: {output.strip()[-300:]}")
    audit.info("host: OS upgrade started")
    with _lock:
        _facts["upgrading"] = True
    return {"started": True}


def upgrade_status(client) -> dict:
    _require()
    code, output = run(
        client,
        f"echo \"state:$(systemctl is-active {UPGRADE_UNIT} 2>/dev/null)\"; tail -c 6000 {UPGRADE_LOG} 2>/dev/null",
    )
    first, _, log_text = output.partition("\n")
    state = first.partition(":")[2].strip()
    running = state in ("active", "activating")
    exit_line = re.search(r"exit: (\d+)\s*$", log_text)
    if not running:
        try:
            refresh_facts(client)
        except Exception:  # noqa: BLE001
            pass
    return {
        "running": running,
        "exit_code": int(exit_line[1]) if exit_line and not running else None,
        "log": log_text,
    }


# --- power -----------------------------------------------------------------------

def power(client, action: str) -> dict:
    """Reboot or power off, a few seconds from now, as a systemd timer —
    so this answers first and nothing in a container has to survive it."""
    _require()
    command = {"reboot": "systemctl reboot", "poweroff": "systemctl poweroff"}.get(action)
    if not command:
        raise HostError("action must be reboot or poweroff")
    code, output = run(client, f"systemd-run --on-active=5 --collect --quiet {command} && echo scheduled")
    if "scheduled" not in output:
        raise HostError(f"couldn't schedule it: {output.strip()[-300:]}")
    audit.info("host: %s scheduled", action)
    return {"scheduled": action, "in_seconds": 5}
