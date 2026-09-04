"""Asynchronous Docker stack configuration backup.

Every ``BACKUP_INTERVAL_HOURS`` the agent discovers the Compose projects on
its host, copies their definition files (redacting secrets), writes an
``inventory.json`` manifest, and pushes ``machines/<HOST_NAME>/`` to a
private GitHub repository.

The agent only ever writes its own ``machines/<HOST_NAME>/`` subtree, so
many hosts can back up to the same repository without conflicting.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time


class BackupError(Exception):
    pass


COMPOSE_NAMES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}

EXCLUDE_DIRS = {
    ".git", ".github", ".gitlab", ".hg", ".svn",
    ".venv", "venv", "virtualenv", "site-packages",
    "node_modules", "bower_components", "vendor",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", ".svelte-kit", ".cache", ".terraform",
    "dist", "build", "target", "out", "coverage",
    "data", "database", "db", "datadir", "logs", "log",
}

EXCLUDE_DIR_SUFFIXES = (".dist-info", ".egg-info")

# Build metadata and lockfiles are never deployment configuration.
EXCLUDE_FILES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
    "composer.json", "composer.lock",
    "poetry.lock", "pdm.lock", "uv.lock", "cargo.lock",
    "gemfile.lock", "go.sum",
    "tsconfig.json", "jsconfig.json",
}

COMPOSE_SUFFIXES = {".yml", ".yaml"}
JSON_MAX_DEPTH = 3

MAX_FILE_BYTES = 512 * 1024
WALK_MAX_DEPTH = 4

_SECRET_LINE = re.compile(
    r"^(?P<prefix>\s*-?\s*)"
    r"(?P<name>[A-Za-z0-9_]*"
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)"
    r"[A-Za-z0-9_]*)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE,
)

# Values that are plainly not secrets even under a sensitive-looking name.
_KEEP_VALUE = re.compile(
    r"""^(?:
        ["']?-?\d[\d_.eE+-]*["']?
        | true | false | null | none | ~ | yes | no
        | \$?\{[^}]+\}
        | \$[A-Za-z_]\w*
        | ["']\s*["']
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Names that contain a sensitive word but denote counts, paths, or headers.
_NAME_NOT_SECRET = re.compile(
    r"MAX_TOKENS?|NUM_TOKENS|_TOKENS(?:_|\b)|TOKEN_HEADER|TOKEN_NAME"
    r"|TOKEN_URL|TOKEN_PATH|TOKEN_TTL|TOKEN_LIMIT|TOKEN_EXPIR"
    r"|PUBLIC_KEY|KEY_PATH|KEY_FILE|KEYMAP|HOTKEY",
    re.IGNORECASE,
)

# Bare keys common in app config (e.g. homepage widgets: "key: <api key>").
_SECRET_BARE = re.compile(
    r"^(?P<prefix>\s*-?\s*)"
    r"(?P<name>key|apikey|api_key|pass|pwd|passwd|password|secret|token)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE,
)

_SECRET_URL = re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@")

_DANGER = re.compile(
    r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
)


def _redact_assignment(match):
    name = match.group("name")
    value = match.group("value").strip()

    if (
        not value
        or _KEEP_VALUE.match(value)
        or _NAME_NOT_SECRET.search(name)
    ):
        return match.group(0)

    return f"{match.group('prefix')}{name}{match.group('sep')}REDACTED"


def _redact(text):
    text = _SECRET_LINE.sub(_redact_assignment, text)
    text = _SECRET_BARE.sub(_redact_assignment, text)
    text = _SECRET_URL.sub(r"\1REDACTED:REDACTED@", text)
    return text


def _wants_file(filename, depth):
    lowered = filename.lower()

    if lowered in EXCLUDE_FILES:
        return False

    suffix = os.path.splitext(lowered)[1]

    if suffix in COMPOSE_SUFFIXES:
        return True

    return suffix == ".json" and depth <= JSON_MAX_DEPTH


def _prune_dirs(names):
    return [
        name
        for name in names
        if name not in EXCLUDE_DIRS
        and not name.lower().endswith(EXCLUDE_DIR_SUFFIXES)
    ]


def _sanitize(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "").strip("_")
    return cleaned or "unnamed"


def _env_bool(name, default):
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


class StackBackup:
    def __init__(self, docker_client, host_name, inventory_provider):
        self.client = docker_client
        self.host = host_name
        self.inventory_provider = inventory_provider

        self.enabled = _env_bool("BACKUP_ENABLED", True)
        self.repo = os.getenv("BACKUP_REPO", "").strip()
        self.branch = os.getenv("BACKUP_BRANCH", "main").strip() or "main"
        self.token = os.getenv("GITHUB_TOKEN", "").strip()

        try:
            hours = float(os.getenv("BACKUP_INTERVAL_HOURS", "12"))
        except ValueError:
            hours = 12.0

        self.interval_seconds = max(300, int(hours * 3600))
        self.host_root = os.getenv("HOST_ROOT", "/host").rstrip("/")
        self.workdir = os.getenv("BACKUP_WORKDIR", "/data/repo")
        self.run_on_start = _env_bool("BACKUP_RUN_ON_START", True)

        try:
            self.start_delay = max(0, int(os.getenv("BACKUP_START_DELAY", "45")))
        except ValueError:
            self.start_delay = 45

        self.author_name = os.getenv("GIT_AUTHOR_NAME", "homelab-agent")
        self.author_email = os.getenv(
            "GIT_AUTHOR_EMAIL",
            "homelab-agent@users.noreply.github.com",
        )

        extra = os.getenv("STACK_DIRS", "")
        self.extra_dirs = [
            part.strip()
            for part in re.split(r"[:\n,]", extra)
            if part.strip()
        ]

        self._lock = threading.Lock()
        self._trigger = threading.Event()
        self._status = {
            "enabled": self.enabled,
            "configured": self.configured,
            "repo": self.repo or None,
            "branch": self.branch,
            "interval_hours": round(self.interval_seconds / 3600, 2),
            "host_folder": f"machines/{_sanitize(self.host)}",
            "running": False,
            "last_run_at": None,
            "last_success_at": None,
            "last_result": None,
            "last_error": None,
            "last_commit": None,
            "projects": None,
        }

    @property
    def configured(self):
        return bool(self.enabled and self.repo and self.token)

    def snapshot(self):
        status = dict(self._status)
        status["configured"] = self.configured
        return status

    def start(self):
        if not self.enabled:
            print("stack backup disabled (BACKUP_ENABLED=false)")
            return

        if not self.configured:
            print(
                "stack backup idle: set BACKUP_REPO and GITHUB_TOKEN "
                "to enable pushing"
            )

        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()

    def trigger(self):
        if not self.configured:
            return False

        self._trigger.set()
        return True

    def _loop(self):
        if self.run_on_start:
            self._trigger.wait(self.start_delay)

        while True:
            self._trigger.clear()

            if self.configured:
                self.run_once()

            self._trigger.wait(self.interval_seconds)

    def run_once(self):
        if not self._lock.acquire(blocking=False):
            return

        staging = None

        try:
            self._status["running"] = True
            self._status["last_run_at"] = time.time()

            staging = tempfile.mkdtemp(prefix="homelab-backup-")
            projects = self._collect(staging)
            self._status["projects"] = projects

            result = self._sync(staging)

            self._status["last_result"] = result
            self._status["last_error"] = None
            self._status["last_success_at"] = time.time()
            print(f"stack backup: {result}")

        except Exception as error:  # noqa: BLE001
            self._status["last_error"] = str(error)
            print(f"stack backup failed: {error}")

        finally:
            self._status["running"] = False

            if staging and os.path.isdir(staging):
                shutil.rmtree(staging, ignore_errors=True)

            self._lock.release()

    # -- collection -------------------------------------------------------

    def _host_path(self, absolute):
        if not absolute:
            return None

        if self.host_root in ("", "/"):
            return absolute

        return os.path.join(self.host_root, absolute.lstrip("/"))

    def _discover(self):
        projects = {}

        def entry_for(name):
            return projects.setdefault(
                name,
                {"working_dir": None, "config_files": set()},
            )

        for container in self.client.containers.list(all=True):
            labels = (
                (container.attrs.get("Config") or {}).get("Labels") or {}
            )

            name = labels.get("com.docker.compose.project")

            if not name:
                continue

            entry = entry_for(name)

            working_dir = labels.get(
                "com.docker.compose.project.working_dir"
            )

            if working_dir and not entry["working_dir"]:
                entry["working_dir"] = working_dir

            config_files = labels.get(
                "com.docker.compose.project.config_files"
            )

            if config_files:
                for path in config_files.split(","):
                    path = path.strip()

                    if path:
                        entry["config_files"].add(path)

        for directory in self.extra_dirs:
            container_dir = self._host_path(directory)

            if not container_dir or not os.path.isdir(container_dir):
                continue

            for root, dirs, files in os.walk(container_dir):
                dirs[:] = _prune_dirs(dirs)

                if root[len(container_dir):].count(os.sep) >= WALK_MAX_DEPTH:
                    dirs[:] = []

                for filename in files:
                    if filename not in COMPOSE_NAMES:
                        continue

                    relative = os.path.relpath(root, container_dir)
                    host_dir = os.path.normpath(
                        os.path.join(directory, relative)
                    )
                    name = os.path.basename(host_dir)

                    entry = entry_for(name)

                    if not entry["working_dir"]:
                        entry["working_dir"] = host_dir

                    entry["config_files"].add(
                        os.path.join(host_dir, filename)
                    )

        return projects

    def _collect(self, staging):
        projects = self._discover()
        written = 0

        for name, entry in sorted(projects.items()):
            target = os.path.join(staging, _sanitize(name))

            if self._collect_project(entry, target):
                written += 1
            else:
                shutil.rmtree(target, ignore_errors=True)

        inventory = self.inventory_provider() or {}

        if isinstance(inventory, dict):
            inventory.pop("generated_at", None)

        with open(
            os.path.join(staging, "inventory.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(inventory, handle, indent=2, sort_keys=True)
            handle.write("\n")

        if projects and written == 0:
            raise BackupError(
                "found Compose projects but could not read any files; "
                f"is the host filesystem mounted at {self.host_root}?"
            )

        return written

    def _collect_project(self, entry, target):
        seen = set()
        count = 0

        working_dir = entry.get("working_dir")
        wd_container = self._host_path(working_dir) if working_dir else None

        def copy_file(container_path, relative):
            nonlocal count

            if relative in seen:
                return

            try:
                if os.path.getsize(container_path) > MAX_FILE_BYTES:
                    return

                with open(
                    container_path,
                    "r",
                    encoding="utf-8",
                    errors="replace",
                ) as handle:
                    content = handle.read()

            except OSError:
                return

            if _DANGER.search(content):
                print(
                    f"stack backup: skipped {relative} "
                    "(matched a private key / token pattern)"
                )
                return

            destination = os.path.join(target, relative)
            os.makedirs(os.path.dirname(destination), exist_ok=True)

            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(_redact(content))

            seen.add(relative)
            count += 1

        for host_path in sorted(entry.get("config_files") or []):
            container_path = self._host_path(host_path)

            if container_path and os.path.isfile(container_path):
                copy_file(container_path, os.path.basename(host_path))

        if wd_container and os.path.isdir(wd_container):
            for root, dirs, files in os.walk(wd_container):
                dirs[:] = _prune_dirs(dirs)

                depth = root[len(wd_container):].count(os.sep)

                if depth >= WALK_MAX_DEPTH:
                    dirs[:] = []

                for filename in files:
                    if not _wants_file(filename, depth):
                        continue

                    full = os.path.join(root, filename)
                    copy_file(full, os.path.relpath(full, wd_container))

        return count

    # -- git sync -------------------------------------------------------

    def _git(self, args, cwd=None, check=True, authed=False):
        command = ["git"]

        if authed and self.token:
            basic = base64.b64encode(
                f"x-access-token:{self.token}".encode()
            ).decode()
            command += [
                "-c",
                "http.https://github.com/.extraheader="
                f"AUTHORIZATION: basic {basic}",
            ]

        command += args

        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
        )

        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()

            if self.token:
                detail = detail.replace(self.token, "***")

            raise BackupError(f"git {args[0]}: {detail}")

        return result

    def _ensure_clone(self):
        url = f"https://github.com/{self.repo}.git"

        if os.path.isdir(os.path.join(self.workdir, ".git")):
            self._git(
                ["remote", "set-url", "origin", url],
                cwd=self.workdir,
            )
            return

        parent = os.path.dirname(self.workdir) or "."
        os.makedirs(parent, exist_ok=True)

        if os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)

        self._git(
            [
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--branch",
                self.branch,
                url,
                self.workdir,
            ],
            authed=True,
        )
        self._git(
            ["config", "user.name", self.author_name],
            cwd=self.workdir,
        )
        self._git(
            ["config", "user.email", self.author_email],
            cwd=self.workdir,
        )

    def _sync(self, staging):
        self._ensure_clone()

        machine_rel = os.path.join("machines", _sanitize(self.host))
        machine_abs = os.path.join(self.workdir, machine_rel)
        last_error = "unknown error"

        for attempt in range(5):
            self._git(
                ["fetch", "--depth", "1", "origin", self.branch],
                cwd=self.workdir,
                authed=True,
            )
            self._git(
                ["reset", "--hard", f"origin/{self.branch}"],
                cwd=self.workdir,
            )
            self._git(
                ["clean", "-fd", "--", "machines"],
                cwd=self.workdir,
                check=False,
            )

            shutil.rmtree(machine_abs, ignore_errors=True)
            shutil.copytree(staging, machine_abs)

            self._git(["add", "--", machine_rel], cwd=self.workdir)

            unchanged = self._git(
                ["diff", "--cached", "--quiet", "--", machine_rel],
                cwd=self.workdir,
                check=False,
            )

            if unchanged.returncode == 0:
                head = self._git(
                    ["rev-parse", "HEAD"], cwd=self.workdir
                ).stdout.strip()
                self._status["last_commit"] = head
                return "no changes"

            self._git(
                [
                    "commit",
                    "-m",
                    f"backup({self.host}): update stacks and inventory",
                ],
                cwd=self.workdir,
            )

            push = self._git(
                ["push", "origin", f"HEAD:{self.branch}"],
                cwd=self.workdir,
                authed=True,
                check=False,
            )

            if push.returncode == 0:
                head = self._git(
                    ["rev-parse", "HEAD"], cwd=self.workdir
                ).stdout.strip()
                self._status["last_commit"] = head
                return f"pushed {head[:10]}"

            last_error = (push.stderr or push.stdout or "").strip()

            if self.token:
                last_error = last_error.replace(self.token, "***")

            time.sleep(2 * (attempt + 1))

        raise BackupError(f"push rejected after retries: {last_error}")
