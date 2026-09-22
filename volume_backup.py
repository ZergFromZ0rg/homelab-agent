"""Back a named volume or a host directory up, here or on another node.

**Two kinds of source, because that is how homelabs actually look.** A
named volume is the tidy case. A great deal of real data sits in a bind
mount instead — ``./data/qdrant:/qdrant/storage`` in somebody's compose
file — and a backup feature that can't see those is a backup feature that
misses the thing you most wanted backed up. A directory source is opt-in
per host via ``BACKUP_SOURCE_DIRS``: not because the agent couldn't
otherwise read the path (it mounts the host read-only already, and anyone
who can call these routes can mount anything through the socket) but
because *sending* a directory to another machine deserves a deliberate
decision naming which directories.

Three more things had to be decided before any of this could be written
down.

**Where a backup is allowed to land.** ``BACKUP_DIRS`` lists paths *inside
this container*, and each one has to be a bind mount from the host. That
looks like an extra hop compared to naming host paths directly, and it is
the whole safety story: the agent receives archives over HTTP and writes
them itself, so an unconstrained destination would be an
arbitrary-file-write primitive on the host. A path can only be written if
somebody deliberately mounted it into the agent, which is a decision made
in ``compose.yml`` by a person, not in a request. Unset means this host
stores no backups and says so — opt-in per host, like ``REBUILD_ENABLED``.

**Who does the writing.** Reading a volume needs it mounted, and the agent
can't mount anything into its own running container, so a throwaway helper
does that half — the pattern ``rebuild.py`` established. When the
destination is on *this* host the helper also writes the archive, with the
destination bound at its real host path. When it's on another node the
helper streams the archive to that node's agent instead, and that agent
writes it through its own mount.

**Which path is which.** The agent sees the host's filesystem under
``HOST_ROOT``, but the Docker daemon resolves a bind mount's source on the
host. So a destination has two spellings — ``/backups/bigboy`` inside here,
``/srv/backups/bigboy`` out there — and handing the wrong one to the daemon
gets you an empty directory Docker helpfully creates, with no error. The
container's own mount table maps between them, which is why
``_mount_table`` exists rather than another environment variable to get
wrong.
"""

from __future__ import annotations

import os
import re
import threading
import time
import uuid
from pathlib import Path

from log import log
from log import audit

import deploy
import rebuild

# A backup is I/O against a whole volume; a big one takes a while.
TIMEOUT = 6 * 60 * 60

MAX_JOBS = 30

# Archives are named by the agent, never by the caller, and this is what
# that name is allowed to look like coming back in over HTTP.
ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.tar\.gz$")

SUFFIX = ".tar.gz"


class PolicyError(ValueError):
    """A destination or a name that isn't allowed. Subclasses ValueError
    for the same reason ``deploy.PolicyError`` does — callers that already
    treat a bad request as a ValueError keep working."""


def _split(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[:,\n]", value) if part.strip()]


# Where compose binds BACKUP_HOST_DIR. Fixed, because the point of the
# variable is that nobody has to edit the service definition.
STORE_MOUNT = "/backups"

# compose binds this named volume at STORE_MOUNT when BACKUP_HOST_DIR is
# unset. It is writable, so it would otherwise pass for a real
# destination and archives would vanish into a throwaway volume.
PLACEHOLDER_VOLUME = "agent-backups-unset"


def configured_dirs() -> list[str]:
    """Destination roots this host will write to.

    ``BACKUP_HOST_DIR`` is the one-variable form: setting it makes compose
    bind that directory at ``/backups`` and makes this agent treat
    ``/backups`` as a root. Two settings that always had to agree were one
    setting too many — get them out of step and the agent comes up fine and
    quietly reports that it stores nothing.

    ``BACKUP_DIRS`` still names roots directly, for more than one of them
    or for a mount somebody set up themselves.
    """
    dirs = _split(os.getenv("BACKUP_DIRS", ""))

    if os.getenv("BACKUP_HOST_DIR", "").strip() and STORE_MOUNT not in dirs:
        dirs.append(STORE_MOUNT)

    return dirs


def enabled() -> bool:
    return bool(configured_dirs())


def source_dirs() -> list[str]:
    """Host directories this host will back up, from ``BACKUP_SOURCE_DIRS``.

    Empty means named volumes only, which is the default. A job may name
    any directory at or under one of these.
    """
    return [d.rstrip("/") or "/" for d in _split(os.getenv("BACKUP_SOURCE_DIRS", ""))]


def host_root() -> str:
    return os.getenv("HOST_ROOT", "/host").rstrip("/")


def resolve_source(path: str) -> str:
    """Check a directory source and return the path to hand the daemon.

    Two spellings again, the other way round from a destination: the agent
    checks what is there through ``HOST_ROOT``, and the daemon is given the
    bare host path, because that is the one it resolves a bind mount
    against.
    """
    if not path or not path.startswith("/"):
        raise PolicyError("a backup source must be an absolute path")

    wanted = Path(path.rstrip("/") or "/")

    if ".." in wanted.parts:
        raise PolicyError("a backup source must not contain '..'")

    allowed = source_dirs()

    if not allowed:
        raise PolicyError(
            "this host backs up named volumes only: set BACKUP_SOURCE_DIRS "
            "on its agent to allow backing up a directory"
        )

    inside = Path(host_root() + str(wanted))

    if not inside.is_dir():
        raise PolicyError(f"{path} is not a directory on this host")

    # Resolve through the host mount, then compare in host spelling. A
    # symlink inside an allowed root that points out of it is otherwise a
    # way straight past the allowlist.
    real_inside = inside.resolve()

    try:
        real = "/" + str(real_inside.relative_to(host_root() or "/"))
    except ValueError:
        real = str(real_inside)

    for root in allowed:
        base = Path(root)

        if Path(real) == base or base in Path(real).parents:
            return real

    raise PolicyError(
        f"{path} is not under a backup source directory ({', '.join(allowed)})"
    )


def _mount_table(client) -> dict[str, str]:
    """Container path -> host path, for this agent's own writable mounts.

    Read from the container rather than configured, because the two
    spellings of a destination have to agree and only Docker knows both.
    """
    own_id = os.getenv("HOSTNAME", "").strip()

    if not own_id:
        return {}

    try:
        mounts = client.containers.get(own_id).attrs.get("Mounts") or []
    except Exception as error:  # noqa: BLE001 - docker-py raises broadly
        log.debug("could not read this agent's mounts: %s", error)
        return {}

    table = {}

    for mount in mounts:
        destination = (mount.get("Destination") or "").rstrip("/")
        source = (mount.get("Source") or "").rstrip("/")

        # The stand-in compose binds when no host directory was chosen. It
        # is a perfectly good writable mount, which is the problem: left in
        # the table it reads as a configured destination and backups go
        # quietly into a volume nobody will think to look in.
        if (mount.get("Name") or "").endswith(PLACEHOLDER_VOLUME):
            continue

        if destination and source and mount.get("RW"):
            table[destination] = source

    return table


def roots(client) -> list[dict]:
    """Every configured destination root, with why it can't be used if it
    can't. A root that isn't a writable bind mount is reported, not hidden
    — the fix is one line of compose and the person needs to be told."""
    table = _mount_table(client)
    out = []

    for configured in configured_dirs():
        path = configured.rstrip("/") or "/"
        host_path = table.get(path)
        problem = None

        if host_path is None:
            problem = (
                f"{path} is not backed by a directory on this host — set "
                "BACKUP_HOST_DIR in the agent's .env to the directory "
                "archives should be written to, then restart it"
                if path == STORE_MOUNT else
                f"{path} is not a writable bind mount in this agent — add "
                f"'- /your/host/path:{path}' to the agent's volumes"
            )
        elif not Path(path).is_dir():
            problem = f"{path} is mounted but does not exist"

        out.append({
            "path": path,
            "host_path": host_path,
            "usable": problem is None,
            "problem": problem,
        })

    return out


def resolve(client, directory: str) -> tuple[Path, str]:
    """Check a destination and return (container path, host path).

    The directory may be a root or anything under one. Symlinks are
    resolved before the comparison, because a symlink inside a writable
    mount pointing out of it would otherwise be a way straight out of the
    allowlist.
    """
    if not directory or not directory.startswith("/"):
        raise PolicyError("a backup directory must be an absolute path")

    if ".." in Path(directory).parts:
        raise PolicyError("a backup directory must not contain '..'")

    usable = [root for root in roots(client) if root["usable"]]

    if not usable:
        blocked = [r["problem"] for r in roots(client) if r["problem"]]
        raise PolicyError(
            blocked[0] if blocked else
            "this host stores no backups: set BACKUP_DIRS on its agent"
        )

    wanted = Path(directory)

    for root in usable:
        base = Path(root["path"])

        try:
            relative = wanted.relative_to(base)
        except ValueError:
            continue

        # Resolve what exists of the path. A directory that isn't there yet
        # is fine — it gets created — but any existing component that is a
        # symlink has to still land inside the root.
        probe = base.resolve()
        real_base = probe

        for part in relative.parts:
            probe = (probe / part).resolve() if (probe / part).exists() else probe / part

        try:
            probe.relative_to(real_base)
        except ValueError:
            raise PolicyError(
                f"{directory} resolves outside {root['path']} — refusing to "
                "follow a symlink out of the backup directory"
            )

        host_path = str(Path(root["host_path"]) / relative) if relative.parts \
            else root["host_path"]

        return probe, host_path

    allowed = ", ".join(root["path"] for root in usable)
    raise PolicyError(f"{directory} is not under a backup directory ({allowed})")


def ensure_dir(client, directory: str) -> tuple[Path, str]:
    path, host_path = resolve(client, directory)
    path.mkdir(parents=True, exist_ok=True)
    return path, host_path


# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------


def list_volumes(client) -> list[dict]:
    """Named volumes on this host, and what is using each one.

    ``in_use_by`` is what makes ``stop_containers`` an informed choice
    rather than a guess: a database's volume tarred while it is writing is
    a backup of a torn file.
    """
    try:
        volumes = client.volumes.list()
    except Exception as error:  # noqa: BLE001
        log.warning("could not list volumes: %s", error)
        return []

    users: dict[str, list[str]] = {}

    try:
        for container in client.containers.list(all=True):
            for mount in container.attrs.get("Mounts") or []:
                if mount.get("Type") == "volume" and mount.get("Name"):
                    users.setdefault(mount["Name"], []).append(container.name)
    except Exception as error:  # noqa: BLE001
        log.debug("could not map volumes to containers: %s", error)

    out = []

    for volume in volumes:
        attrs = volume.attrs or {}
        name = attrs.get("Name") or volume.name

        out.append({
            "name": name,
            "driver": attrs.get("Driver"),
            "created_at": attrs.get("CreatedAt"),
            "labels": attrs.get("Labels") or {},
            "project": (attrs.get("Labels") or {}).get(
                "com.docker.compose.project"
            ),
            "in_use_by": sorted(users.get(name, [])),
        })

    return sorted(out, key=lambda v: v["name"])


def archive_name(source: str, when: float | None = None) -> str:
    """``<source>-<stamp>.tar.gz``, where source is a volume name or a path.

    The same sanitiser covers both: a path's slashes become dashes, so
    ``/home/zerg/ai-librarian/data/qdrant`` reads back as
    ``home-zerg-ai-librarian-data-qdrant`` — long, but stable and unique,
    which is what retention matches on.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(when or time.time()))
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", source).strip("-") or "volume"
    return f"{safe}-{stamp}{SUFFIX}"


# ---------------------------------------------------------------------------
# Stored archives
# ---------------------------------------------------------------------------


def check_name(name: str) -> str:
    if not ARCHIVE_NAME.match(name or ""):
        raise PolicyError(f"{name!r} is not a backup archive name")

    return name


def list_archives(client, directory: str) -> list[dict]:
    path, _ = resolve(client, directory)

    if not path.is_dir():
        return []

    out = []

    for entry in path.iterdir():
        if not entry.is_file() or not entry.name.endswith(SUFFIX):
            continue

        try:
            info = entry.stat()
        except OSError:
            continue

        out.append({
            "name": entry.name,
            "bytes": info.st_size,
            "modified_at": info.st_mtime,
        })

    return sorted(out, key=lambda a: a["modified_at"], reverse=True)


def delete_archives(client, directory: str, names: list[str]) -> dict:
    path, _ = resolve(client, directory)
    deleted, missing = [], []

    for name in names:
        check_name(name)
        target = path / name

        if not target.is_file():
            missing.append(name)
            continue

        try:
            target.unlink()
            deleted.append(name)
        except OSError as error:
            raise PolicyError(f"could not delete {name}: {error}")

    if deleted:
        audit.info("backup: deleted %s from %s", ", ".join(deleted), directory)

    return {"deleted": deleted, "missing": missing}


class Receiver:
    """An archive arriving from another node's helper, written as it lands.

    A class rather than a function taking an iterable because the route
    that feeds it is async: the bytes arrive from the event loop and each
    write goes to a worker thread, so there is no point in the request
    where the whole archive exists anywhere.

    The bytes are hashed on the way past and the digest is returned, so
    the sender can tell whether what landed is what it sent. Written to
    ``.part`` and renamed at the end, so an interrupted upload leaves
    something plainly incomplete rather than a truncated archive that
    looks finished.
    """

    def __init__(self, client, directory: str, name: str):
        import hashlib

        check_name(name)
        path, _ = ensure_dir(client, directory)

        self.directory = directory
        self.name = name
        self.target = path / name
        self.partial = path / f"{name}.part"
        self.digest = hashlib.sha256()
        self.bytes = 0
        self._handle = open(self.partial, "wb")

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return

        self.digest.update(chunk)
        self.bytes += len(chunk)
        self._handle.write(chunk)

    def commit(self) -> dict:
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        os.replace(self.partial, self.target)

        audit.info(
            "backup: stored %s (%d bytes) in %s",
            self.name, self.bytes, self.directory,
        )

        return {
            "name": self.name,
            "bytes": self.bytes,
            "sha256": self.digest.hexdigest(),
        }

    def abort(self) -> None:
        try:
            self._handle.close()
        except Exception:  # noqa: BLE001 - already failing
            pass

        self.partial.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def status(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def recent() -> list[dict]:
    with _lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)
        return [dict(job) for job in jobs]


def _running() -> bool:
    return any(job["state"] == "running" for job in _jobs.values())


def _record(job: dict) -> None:
    _jobs[job["id"]] = job

    if len(_jobs) > MAX_JOBS:
        for old in sorted(_jobs.values(), key=lambda j: j["started_at"])[:-MAX_JOBS]:
            if old["state"] != "running":
                _jobs.pop(old["id"], None)


def _finish(job: dict, state: str, error: str | None = None) -> None:
    with _lock:
        job["state"] = state
        job["error"] = error
        job["finished_at"] = time.time()

    level = audit.warning if state == "failed" else audit.info
    level("backup %s %s%s", job["id"], state, f": {error}" if error else "")


def _uses(mounts: list, volume: str | None, path: str | None) -> bool:
    """Whether a container is writing to what we are about to copy.

    For a directory that means any bind mount at, under, or *containing*
    the path — a container mounting the parent writes into it just as
    surely as one mounting it exactly.
    """
    for mount in mounts:
        if volume and mount.get("Name") == volume:
            return True

        if path and mount.get("Type") == "bind":
            source = (mount.get("Source") or "").rstrip("/")

            if source and (
                source == path
                or source.startswith(path + "/")
                or path.startswith(source + "/")
            ):
                return True

    return False


def _quiesce(client, volume: str | None, path: str | None = None) -> tuple[list, list[str]]:
    """Stop the containers writing to the source, newest first.

    A protected container is never stopped — that's what protection means,
    and the agent stopping itself mid-backup would orphan the job. It is
    skipped and named in the job, because a backup taken while something
    was still writing needs to say so.
    """
    stopped, skipped = [], []

    for container in client.containers.list():
        if not _uses(container.attrs.get("Mounts") or [], volume, path):
            continue

        if container.name in deploy.PROTECTED_NAMES:
            skipped.append(container.name)
            continue

        stopped.append(container)

    for container in stopped:
        audit.info(
            "backup: stopping %s to quiesce %s", container.name, volume or path
        )
        container.stop(timeout=30)

    return stopped, skipped


def _resume(stopped: list) -> list[str]:
    failed = []

    for container in reversed(stopped):
        try:
            container.start()
        except Exception as error:  # noqa: BLE001
            failed.append(f"{container.name}: {error}")
            audit.warning("backup: could not restart %s: %s", container.name, error)

    return failed


def start(client, *, volume: str | None = None, path: str | None = None,
          directory: str, remote: dict | None = None,
          name: str | None = None, stop_containers: bool = False) -> dict:
    """Kick off a backup. Returns the job immediately.

    Exactly one of ``volume`` and ``path`` is the source. ``remote`` is
    ``{"url", "token"}`` when the archive belongs on another node; the
    helper streams it there and that node's agent writes it. Without it the
    archive is written here, to ``directory``.
    """
    if bool(volume) == bool(path):
        raise PolicyError("a backup needs either a volume or a path, not both")

    if volume:
        try:
            client.volumes.get(volume)
        except Exception:  # noqa: BLE001 - docker-py raises NotFound broadly
            raise PolicyError(f"no volume named {volume!r} on this host")
        source_host_path = None
    else:
        # Checked now rather than inside the helper, whose output nobody is
        # watching yet.
        source_host_path = resolve_source(path)

    host_path = None

    if remote:
        if not str(remote.get("url", "")).startswith(("http://", "https://")):
            raise PolicyError("a remote destination needs an http(s) agent url")
    else:
        _, host_path = ensure_dir(client, directory)

    with _lock:
        if _running():
            raise RuntimeError("a backup is already running on this host")

        job = {
            "id": uuid.uuid4().hex[:12],
            "volume": volume,
            "path": path,
            "archive": name or archive_name(volume or path),
            "directory": directory,
            "remote_url": (remote or {}).get("url"),
            "stop_containers": bool(stop_containers),
            "stopped": [],
            "not_stopped": [],
            "state": "running",
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
            "error": None,
        }
        _record(job)

    audit.info(
        "backup %s: %s -> %s%s",
        job["id"], volume or path, job["remote_url"] or directory,
        " (stopping its containers)" if stop_containers else "",
    )

    thread = threading.Thread(
        target=_run_job,
        args=(client, job),
        kwargs={
            "host_path": host_path,
            "source_host_path": source_host_path,
            "token": (remote or {}).get("token"),
        },
        daemon=True,
    )
    thread.start()

    return dict(job)


def _run_job(client, job: dict, *, host_path: str | None,
             source_host_path: str | None, token: str | None) -> None:
    try:
        _backup(client, job, host_path=host_path,
                source_host_path=source_host_path, token=token)
    except Exception as error:  # noqa: BLE001 - the thread must not die silently
        _finish(job, "failed", str(error))


def _backup(client, job: dict, *, host_path: str | None,
            source_host_path: str | None, token: str | None) -> None:
    import json as _json

    stopped, skipped = [], []

    if job["stop_containers"]:
        stopped, skipped = _quiesce(client, job["volume"], job.get("path"))

        with _lock:
            job["stopped"] = [c.name for c in stopped]
            job["not_stopped"] = skipped

    environment = {"BACKUP_NAME": job["archive"]}
    # A volume is bound by name; a directory by its real host path, which
    # resolve_source() has already checked and translated out of HOST_ROOT.
    volumes = {
        (job["volume"] or source_host_path): {"bind": "/src", "mode": "ro"}
    }

    if job["remote_url"]:
        environment["BACKUP_DEST_URL"] = job["remote_url"]
        environment["BACKUP_DEST_DIR"] = job["directory"]

        if token:
            environment["BACKUP_TOKEN"] = token
    else:
        # The *host* spelling of the destination. Handing the daemon this
        # container's spelling would silently create an empty directory on
        # the host and write the archive into a path nothing else can see.
        volumes[host_path] = {"bind": "/dest", "mode": "rw"}

    container = None

    try:
        container = client.containers.run(
            rebuild.helper_image(client),
            command=["python", "/app/backup_helper.py"],
            detach=True,
            environment=environment,
            volumes=volumes,
            labels={"homelab-agent-backup": job["id"]},
        )

        result = container.wait(timeout=TIMEOUT)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        output = container.logs().decode("utf-8", "replace").strip()

    except Exception as error:  # noqa: BLE001
        _resume(stopped)
        _finish(job, "failed", f"the backup helper failed to run: {error}")
        return

    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception as error:  # noqa: BLE001 - best effort
                log.debug("could not remove backup helper: %s", error)

    restart_errors = _resume(stopped)

    # The helper's last line is its JSON result; anything before it is
    # noise from the runtime and shouldn't hide the answer.
    parsed = {}

    for line in reversed(output.splitlines()):
        try:
            parsed = _json.loads(line)
            break
        except ValueError:
            continue

    if code != 0 or parsed.get("error"):
        _finish(
            job, "failed",
            parsed.get("error") or output[-500:] or f"helper exited {code}",
        )
        return

    with _lock:
        job["result"] = parsed

    if restart_errors:
        _finish(
            job, "failed",
            "the archive was written, but a container did not come back: "
            + "; ".join(restart_errors),
        )
        return

    _finish(job, "succeeded")


def reset() -> None:
    with _lock:
        _jobs.clear()
