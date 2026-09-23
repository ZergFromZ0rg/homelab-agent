"""Settings this agent can be given from the dashboard, and the ones it can't.

The problem this solves: every switch on an agent lived in a ``.env`` file
on the host, so turning a feature on meant an ssh session, an editor and a
``docker compose up -d``. That is a bad experience, and worse, it fails
*silently* — an edit that lands in the wrong place leaves the agent healthy
and quietly not doing the thing.

**Why an overlay instead of rewriting .env.** An agent that can rewrite its
own environment and restart itself is, in practice, remote code execution
on the host: ``AGENT_RUNTIME``, ``REBUILD_ENABLED`` and the deploy
allowlists all turn into arbitrary code the moment they can be set
remotely. So nothing here touches ``.env``, compose, or the container.
Settings are written to a JSON file on the agent's *own* volume and read
back at call time, layered over the environment. The blast radius is this
process, and the worst a caller can do is misconfigure the agent.

**What that costs.** Anything the container environment fixes at start —
a bind mount, the runtime, the bind address — cannot be changed this way,
because compose read it before this process existed. Those are reported as
``scope: "host"`` with the exact line to add, rather than pretended at.
That set is deliberately small, and ``install.sh`` sets it at join time so
a new node arrives ready.

**Writing is opt-in**, ``CONFIG_WRITABLE=1``, the same shape as
``REBUILD_ENABLED``: a host says once, by hand, that it accepts settings
from the dashboard. Reading is always allowed, so the UI can show what is
set and explain what to do about the rest.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from log import log, audit

CONFIG_FILE = Path(os.getenv("AGENT_CONFIG_FILE", "/data/config.json"))

TRUTHY = ("1", "true", "yes", "on")

# Never a backup destination or a source root: handing any of these over
# turns a misconfiguration into a compromised host.
FORBIDDEN_PATHS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
    "/run", "/sbin", "/sys", "/usr", "/var", "/var/run", "/var/lib/docker",
}

_lock = threading.Lock()
_cache: dict | None = None


# ---------------------------------------------------------------------------
# What may be set
# ---------------------------------------------------------------------------
#
# ``scope``:
#   live  read at call time, so a change applies to the next request
#   host  fixed by the container's environment; shown, never written
#
# Keeping the two in one list is the point. A settings page that only shows
# what it can change leaves someone hunting for the switch that isn't there.

SETTINGS: list[dict] = [
    {
        "key": "BACKUP_SOURCE_DIRS", "kind": "paths", "scope": "live",
        "group": "Backups", "label": "Directories this host may back up",
        "help": "Adds host directories to the named volumes already offered. "
                "A job may use one of these or anything under it. Empty means "
                "named volumes only.",
    },
    {
        "key": "BACKUP_PASSPHRASE", "kind": "secret", "scope": "live",
        "group": "Backups", "label": "Encrypt backups with this passphrase",
        "help": "Set it and every archive this host writes or receives is "
                "encrypted with gpg. Set the SAME value on every host, or a "
                "host cannot check an archive another one sent it. "
                "LOSE IT AND EVERY ENCRYPTED ARCHIVE IS UNREADABLE — there is "
                "no recovery, by design.",
        "danger": True,
    },
    {
        "key": "BACKUP_DIRS", "kind": "paths", "scope": "live",
        "group": "Backups", "label": "Extra destinations",
        "help": "Only needed for a second backup disk, or a mount you set up "
                "yourself. The usual destination comes from the backup "
                "directory below.",
    },
    {
        "key": "BACKUP_PUBLIC_URL", "kind": "url", "scope": "live",
        "group": "Backups", "label": "Address other hosts reach this agent at",
        "help": "Needed when this agent registers under a name only the "
                "dashboard's own network resolves, such as a container name. "
                "It is another host's helper that connects here.",
    },
    {
        "key": "BACKUP_HOST_DIR", "kind": "path", "scope": "host",
        "group": "Backups", "label": "Backup directory on this machine",
        "help": "Which disk backups live on. Fixed when the container "
                "started, because it is a bind mount.",
    },
    {
        "key": "BACKUP_REPO", "kind": "text", "scope": "live",
        "group": "Config backup", "label": "Repository",
        "help": "owner/name of a private repo for this host's compose files.",
    },
    {
        "key": "GITHUB_TOKEN", "kind": "secret", "scope": "live",
        "group": "Config backup", "label": "GitHub token",
        "help": "Fine-grained PAT with Contents: read and write, on that "
                "repository only.",
    },
    {
        "key": "BACKUP_INTERVAL_HOURS", "kind": "number", "scope": "live",
        "group": "Config backup", "label": "How often", "min": 1, "max": 168,
        "help": "Hours between config backups.",
    },
    {
        "key": "STACK_DIRS", "kind": "paths", "scope": "live",
        "group": "Config backup", "label": "Extra stack directories",
        "help": "Compose projects outside the ones Docker reports.",
    },
    {
        "key": "REBUILD_ENABLED", "kind": "bool", "scope": "live",
        "group": "Updates", "label": "Allow rebuilds from the dashboard",
        "help": "Lets the dashboard pull and rebuild this host's compose "
                "projects. That runs whatever the repo and its Dockerfile "
                "say, as root on this host.",
        "danger": True,
    },
    {
        "key": "CONNECTIONS_ENABLED", "kind": "bool", "scope": "live",
        "group": "Monitoring", "label": "Report network conversations",
        "help": "Powers the Connections panel on this host's card.",
    },
    {
        "key": "HOST_NAME", "kind": "text", "scope": "host",
        "group": "Identity", "label": "Host name",
        "help": "Must match this host's Prometheus job name. Changing it "
                "would orphan every metric already recorded under the old one.",
    },
    {
        "key": "AGENT_RUNTIME", "kind": "text", "scope": "host",
        "group": "Identity", "label": "Container runtime",
        "help": "nvidia on a host with an NVIDIA card and the container "
                "toolkit. Fixed when the container started.",
    },
    {
        "key": "AGENT_TOKEN", "kind": "secret", "scope": "host",
        "group": "Identity", "label": "Shared token",
        "help": "Gates every mutating route. Read once at startup, and "
                "changing it from here could lock the dashboard out.",
    },
    {
        "key": "LOG_LEVEL", "kind": "text", "scope": "host",
        "group": "Identity", "label": "Log level",
        "help": "Logging is configured once, at startup.",
    },
]

BY_KEY = {s["key"]: s for s in SETTINGS}


def writable() -> bool:
    return os.getenv("CONFIG_WRITABLE", "").strip().lower() in TRUTHY


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _load() -> dict:
    global _cache

    with _lock:
        if _cache is None:
            try:
                data = json.loads(CONFIG_FILE.read_text())
                _cache = data if isinstance(data, dict) else {}
            except (OSError, ValueError):
                _cache = {}

        return dict(_cache)


def get(name: str, default: str = "") -> str:
    """A setting, overlay first, then the environment.

    This is a drop-in for ``os.getenv(name, default)`` and is deliberately
    string-in/string-out so the call sites keep their own parsing — the
    overlay should not quietly change what a value means.
    """
    stored = _load().get(name)

    if stored is not None and str(stored).strip() != "":
        return str(stored)

    return os.getenv(name, default)


def reload() -> None:
    global _cache

    with _lock:
        _cache = None


# ---------------------------------------------------------------------------
# Validating
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """A setting that was refused, with the reason a person needs."""


def _clean_paths(value: str, label: str) -> str:
    out = []

    for raw in re.split(r"[:,\n]", value or ""):
        trimmed = raw.strip()

        if not trimmed:
            continue

        # Strip the trailing slash *after* the empty check, so "/" arrives
        # here as the root it is and gets refused below rather than
        # becoming "" and vanishing with no explanation.
        path = trimmed.rstrip("/") or "/"

        if not path.startswith("/"):
            raise ConfigError(f"{label}: {raw.strip()!r} is not an absolute path")

        if ".." in Path(path).parts:
            raise ConfigError(f"{label}: {raw.strip()!r} must not contain '..'")

        if path in FORBIDDEN_PATHS or (path or "/") == "/":
            raise ConfigError(
                f"{label}: {path} is a system directory — naming it here would "
                "hand over the whole host, which is never what a backup wants"
            )

        out.append(path)

    return ",".join(out)


def _clean(setting: dict, value) -> str:
    kind = setting["kind"]
    label = setting["label"]
    text = "" if value is None else str(value).strip()

    if kind in ("paths",):
        return _clean_paths(text, label)

    if kind == "path":
        return _clean_paths(text, label) if text else ""

    if kind == "bool":
        if isinstance(value, bool):
            return "1" if value else ""
        return "1" if text.lower() in TRUTHY else ""

    if kind == "number":
        if not text:
            return ""

        try:
            number = float(text)
        except ValueError:
            raise ConfigError(f"{label}: {text!r} is not a number")

        low, high = setting.get("min"), setting.get("max")

        if low is not None and number < low:
            raise ConfigError(f"{label}: must be at least {low}")

        if high is not None and number > high:
            raise ConfigError(f"{label}: must be at most {high}")

        return str(int(number) if number.is_integer() else number)

    if kind == "url":
        if text and not text.startswith(("http://", "https://")):
            raise ConfigError(f"{label}: must start with http:// or https://")

        return text.rstrip("/")

    if len(text) > 500:
        raise ConfigError(f"{label}: too long")

    return text


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def update(changes: dict) -> dict:
    """Apply settings. Returns the keys that actually changed.

    All-or-nothing: every value is validated before any is written, so a
    form with one bad field doesn't half-apply.
    """
    if not writable():
        raise ConfigError(
            "this host does not accept settings from the dashboard — set "
            "CONFIG_WRITABLE=1 in its agent's .env and restart it"
        )

    if not isinstance(changes, dict):
        raise ConfigError("expected an object of settings")

    cleaned: dict[str, str] = {}

    for key, value in changes.items():
        setting = BY_KEY.get(key)

        if setting is None:
            raise ConfigError(f"{key} is not a setting this agent accepts")

        if setting["scope"] != "live":
            raise ConfigError(
                f"{setting['label']} is fixed by this container's environment "
                "and cannot be changed from here"
            )

        cleaned[key] = _clean(setting, value)

    before = _load()
    applied = [k for k, v in cleaned.items() if before.get(k, "") != v]

    if not applied:
        return {"applied": [], "settings": current()}

    merged = {**before, **cleaned}
    # An empty value means "unset" — keep the file to what is actually set
    # rather than accumulating blanks that read as configuration.
    merged = {k: v for k, v in merged.items() if str(v).strip()}

    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
        tmp.replace(CONFIG_FILE)
    except OSError as error:
        raise ConfigError(f"could not save settings: {error}")

    global _cache

    with _lock:
        _cache = merged

    for key in applied:
        shown = "<set>" if BY_KEY[key]["kind"] == "secret" else (merged.get(key) or "<unset>")
        audit.info("config: %s = %s", key, shown)

    return {"applied": sorted(applied), "settings": current()}


def current() -> list[dict]:
    """Every setting with its effective value and where that value came from.

    ``source`` matters to whoever is looking: a value from the environment
    can be overridden here, one already set here can be cleared, and a
    ``host`` setting can only be changed where it was set.
    """
    stored = _load()
    out = []

    for setting in SETTINGS:
        key = setting["key"]
        overlaid = str(stored.get(key, "")).strip()
        env = os.getenv(key, "").strip()
        value = overlaid or env
        secret = setting["kind"] == "secret"

        out.append({
            **{k: v for k, v in setting.items() if k != "kind"},
            "kind": setting["kind"],
            # A secret is never handed back, only whether there is one.
            "value": ("" if secret else value),
            "set": bool(value),
            "source": "dashboard" if overlaid else ("environment" if env else "unset"),
            "editable": setting["scope"] == "live" and writable(),
        })

    return out


def snapshot() -> dict:
    return {
        "writable": writable(),
        "why_not": None if writable() else (
            "This host does not accept settings from the dashboard. Add "
            "CONFIG_WRITABLE=1 to its agent's .env and restart it, or set it "
            "at join time with install.sh."
        ),
        "settings": current(),
    }
