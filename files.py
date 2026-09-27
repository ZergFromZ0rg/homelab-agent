"""The file browser: list, read, download, and — inside allowed roots —
write, upload, rename and make folders.

Reading goes through the read-only ``/:/host`` mount, like the disk
explorer, and is allowed anywhere it is. **Writing is scoped.** A path is
writable only under a *root*:

- the home folder of whoever owns this agent's checkout (the person who
  installed it),
- every Compose project folder on this host (where the configs live),
- ``STACK_DIRS``, and ``FILES_WRITABLE_PATHS`` for anything else.

Never ``/`` and never an operating-system folder, whatever the roots say.
No symlinks anywhere on the way down, so a link can't carry a write out of
its root.

**Writes run as the owner, not as root.** The agent's own view of the host
stays read-only; a write is a throwaway helper container with just the
folder bind-mounted, network off, running as the uid that owns the file
(or, for a new one, the folder). A root helper writing into someone's
home leaves root-owned files behind — the rebuild helper did exactly that
for weeks before anyone noticed.

**Saving keeps the inode.** New content is dropped next to the file under
a temporary name (``put_archive`` on a helper that never starts), then
``cat``-ed over the original. Replacing the file instead would silently
break every container that bind-mounts that single file — it would keep
reading the old one.
"""

from __future__ import annotations

import os
import posixpath
import queue
import secrets
import stat
import tarfile
import threading
import time

import config
import disk_usage
import rebuild
from disk_delete import PROTECTED, _container_mounts, _under
from disk_usage import DiskUsageError, normalize
from log import audit, log

TEXT_LIMIT = 2 * 1024 * 1024
LIST_LIMIT = 5000
HELPER_TIMEOUT = 600
ROOTS_CACHE_SECONDS = 30

_roots_cache: tuple[float, list[str]] | None = None


class Conflict(DiskUsageError):
    """The file changed (or already exists) — the caller decides."""


# --- roots ------------------------------------------------------------------


def home_of(uid: int | None) -> str | None:
    """A user's home folder, read from the host's own /etc/passwd."""
    if uid is None:
        return None
    try:
        with open(disk_usage._on_host("/etc/passwd"), encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 6 and parts[2] == str(uid):
                    return parts[5] or None
    except OSError:
        return None
    return None


def _split(value: str) -> list[str]:
    return [p.strip().rstrip("/") for p in value.replace("\n", ",").replace(":", ",").split(",") if p.strip()]


def write_roots(client, owner_uid: int | None) -> list[str]:
    global _roots_cache
    now = time.time()
    if _roots_cache and now - _roots_cache[0] < ROOTS_CACHE_SECONDS:
        return _roots_cache[1]

    roots = set()
    home = home_of(owner_uid)
    if home:
        roots.add(home)
    try:
        for container in client.containers.list(all=True):
            wd = (container.labels or {}).get("com.docker.compose.project.working_dir")
            if wd:
                roots.add(wd)
    except Exception as error:  # noqa: BLE001 - roots are best effort
        log.debug("could not list compose projects for file roots: %s", error)
    roots.update(_split(config.get("STACK_DIRS")))
    roots.update(_split(config.get("FILES_WRITABLE_PATHS")))

    clean = sorted(
        r for r in (posixpath.normpath(r) for r in roots if r.startswith("/"))
        if r != "/" and r not in config.FORBIDDEN_PATHS
        and not any(_under(r, p) for p in PROTECTED)
    )
    _roots_cache = (now, clean)
    return clean


def root_for(path: str, roots: list[str]) -> str | None:
    matches = [r for r in roots if _under(path, r)]
    return max(matches, key=len) if matches else None


def why_not_writable(path: str, roots: list[str]) -> str | None:
    """None when ``path`` may be written; otherwise the reason."""
    if any(_under(path, p) for p in PROTECTED):
        return f"{path} is part of the operating system"
    root = root_for(path, roots)
    if root is None:
        return "outside the folders this host allows writing to (its owner's home and compose stacks)"
    # No symlink between the root and the path, root included.
    current = root
    for part in [""] + path[len(root):].strip("/").split("/"):
        current = posixpath.join(current, part) if part else current
        try:
            if stat.S_ISLNK(os.lstat(disk_usage._on_host(current)).st_mode):
                return f"{current} is a symlink — open where it points instead"
        except FileNotFoundError:
            break
    return None


def _require_writable(path: str, roots: list[str]) -> None:
    reason = why_not_writable(path, roots)
    if reason:
        raise DiskUsageError(reason)


# --- reading ----------------------------------------------------------------


def resolve(path: str, owner_uid: int | None) -> str:
    """``~`` is the owner's home — what the card's folder button opens."""
    if path in ("~", ""):
        return home_of(owner_uid) or "/"
    return normalize(path)


def listing(client, path: str, owner_uid: int | None) -> dict:
    path = resolve(path, owner_uid)
    host_dir = disk_usage._on_host(path)
    roots = write_roots(client, owner_uid)

    try:
        names = os.listdir(host_dir)
    except FileNotFoundError as error:
        raise DiskUsageError(f"{path} doesn't exist") from error
    except NotADirectoryError as error:
        raise DiskUsageError(f"{path} isn't a folder") from error
    except PermissionError as error:
        raise DiskUsageError(f"{path} can't be read") from error

    try:
        dev = os.lstat(host_dir).st_dev
    except OSError:
        dev = None

    entries = []
    for name in sorted(names)[:LIST_LIMIT]:
        full = posixpath.join(path, name)
        try:
            st = os.lstat(os.path.join(host_dir, name))
        except OSError:
            continue
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            kind = "link"
        elif stat.S_ISDIR(mode):
            kind = "mount" if dev is not None and st.st_dev != dev else "dir"
        elif stat.S_ISREG(mode):
            kind = "file"
        else:
            kind = "other"
        entry = {
            "name": name,
            "path": full,
            "kind": kind,
            "size": st.st_size if kind == "file" else None,
            "modified": st.st_mtime,
            "uid": st.st_uid,
        }
        if kind == "link":
            try:
                entry["target"] = os.readlink(os.path.join(host_dir, name))
            except OSError:
                pass
        entries.append(entry)

    reason = why_not_writable(path, roots)
    return {
        "path": path,
        "parent": posixpath.dirname(path) if path != "/" else None,
        "entries": entries,
        "truncated": len(names) > LIST_LIMIT,
        "writable": reason is None,
        "why_not": reason,
        "roots": roots,
        "home": home_of(owner_uid),
    }


def _regular_file(path: str) -> os.stat_result:
    try:
        st = os.lstat(disk_usage._on_host(path))
    except FileNotFoundError as error:
        raise DiskUsageError(f"{path} doesn't exist") from error
    if not stat.S_ISREG(st.st_mode):
        raise DiskUsageError(f"{path} isn't a regular file")
    return st


def read_text(client, path: str, owner_uid: int | None) -> dict:
    path = normalize(path)
    st = _regular_file(path)
    if st.st_size > TEXT_LIMIT:
        raise DiskUsageError(f"too big to edit here ({st.st_size // 1024} KB) — download it instead")
    try:
        with open(disk_usage._on_host(path), "rb") as f:
            raw = f.read(TEXT_LIMIT + 1)
    except PermissionError as error:
        raise DiskUsageError(f"{path} can't be read") from error
    if b"\0" in raw:
        raise DiskUsageError("binary file — download it instead")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DiskUsageError("not UTF-8 text — download it instead") from error
    reason = why_not_writable(path, write_roots(client, owner_uid))
    return {
        "path": path,
        "content": content,
        "size": st.st_size,
        "modified": st.st_mtime,
        "writable": reason is None,
        "why_not": reason,
    }


def open_file(path: str):
    """(file object, size, name) for a download."""
    path = normalize(path)
    st = _regular_file(path)
    try:
        f = open(disk_usage._on_host(path), "rb")
    except PermissionError as error:
        raise DiskUsageError(f"{path} can't be read") from error
    return f, st.st_size, posixpath.basename(path)


class _QueueWriter:
    """File-like sink for tarfile that hands chunks to a generator, with
    backpressure, so a folder streams instead of building up in memory."""

    def __init__(self):
        self.q: queue.Queue = queue.Queue(maxsize=16)
        self.aborted = False

    def write(self, data: bytes) -> int:
        while not self.aborted:
            try:
                self.q.put(bytes(data), timeout=1)
                return len(data)
            except queue.Full:
                continue
        raise OSError("download abandoned")

    def flush(self):
        pass


def folder_archive(path: str):
    """A generator of .tar.gz bytes for a folder. One filesystem, symlinks
    stored as links, unreadable files skipped."""
    path = normalize(path)
    top = disk_usage._on_host(path)
    if not os.path.isdir(top) or os.path.islink(top):
        raise DiskUsageError(f"{path} isn't a folder")
    dev = os.lstat(top).st_dev
    name = posixpath.basename(path) or "root"
    sink = _QueueWriter()

    def produce():
        try:
            with tarfile.open(fileobj=sink, mode="w|gz") as tar:
                for base, dirs, files in os.walk(top):
                    dirs[:] = [d for d in dirs if os.lstat(os.path.join(base, d)).st_dev == dev]
                    for entry in [base] + [os.path.join(base, f) for f in files]:
                        rel = os.path.relpath(entry, top)
                        arcname = name if rel == "." else f"{name}/{rel}"
                        try:
                            tar.add(entry, arcname=arcname, recursive=False)
                        except (OSError, tarfile.TarError) as error:
                            if sink.aborted:
                                raise
                            log.debug("archive: skipped %s: %s", entry, error)
        except Exception as error:  # noqa: BLE001 - the stream just ends
            log.debug("folder archive ended early: %s", error)
        finally:
            while not sink.aborted:
                try:
                    sink.q.put(None, timeout=1)
                    break
                except queue.Full:
                    continue

    threading.Thread(target=produce, daemon=True).start()

    def chunks():
        try:
            while True:
                chunk = sink.q.get()
                if chunk is None:
                    return
                yield chunk
        finally:
            sink.aborted = True

    return chunks(), f"{name}.tar.gz"


# --- writing ----------------------------------------------------------------


def _owner(host_path: str) -> tuple[int, int]:
    st = os.lstat(host_path)
    return st.st_uid, st.st_gid


def _tar_stream(name: str, size: int, source, uid: int, gid: int, mode: int):
    info = tarfile.TarInfo(name)
    info.size = size
    info.uid, info.gid = uid, gid
    info.mode = mode
    info.mtime = time.time()
    yield info.tobuf(format=tarfile.GNU_FORMAT)
    sent = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        sent += len(chunk)
        yield chunk
    if sent != size:
        raise OSError(f"expected {size} bytes, got {sent}")
    if size % 512:
        yield b"\0" * (512 - size % 512)
    yield b"\0" * 1024


def _helper(client, folder: str, command: list[str], uid: int, gid: int):
    return client.containers.create(
        rebuild.helper_image(client),
        command=command,
        user=f"{uid}:{gid}",
        working_dir="/target",
        volumes={folder: {"bind": "/target", "mode": "rw"}},
        network_disabled=True,
        labels={"homelab-agent-files": folder},
    )


def _run(container) -> None:
    try:
        container.start()
        result = container.wait(timeout=HELPER_TIMEOUT)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        if code != 0:
            output = container.logs().decode("utf-8", "replace").strip()
            raise DiskUsageError(output[-300:] or f"the file helper exited {code}")
    finally:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001 - best effort
            pass


# Drops the new content in place: over the old file's inode when there is
# one (so single-file bind mounts see it), else a rename into place.
_PLACE = (
    'tmp="$1"; dst="$2"; '
    'if [ -e "$dst" ]; then cat -- "$tmp" > "$dst" && rm -f -- "$tmp"; '
    'else mv -n -- "$tmp" "$dst"; fi'
)


def write_file(client, path: str, source, size: int, owner_uid: int | None, *,
               overwrite: bool, expected_modified: float | None = None) -> dict:
    """Write ``size`` bytes from ``source`` to ``path``."""
    path = normalize(path)
    folder, name = posixpath.split(path)
    if not name or name in (".", ".."):
        raise DiskUsageError("a file name is required")
    _require_writable(path, write_roots(client, owner_uid))

    host_folder = disk_usage._on_host(folder)
    if not os.path.isdir(host_folder):
        raise DiskUsageError(f"{folder} isn't a folder")
    host_target = os.path.join(host_folder, name)

    if os.path.lexists(host_target):
        st = os.lstat(host_target)
        if not stat.S_ISREG(st.st_mode):
            raise DiskUsageError(f"{path} exists and isn't a regular file")
        if not overwrite:
            raise Conflict(f"{name} already exists")
        if expected_modified is not None and abs(st.st_mtime - expected_modified) > 0.001:
            raise Conflict(f"{name} changed on disk since you opened it")
        uid, gid, mode = st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)
    else:
        uid, gid = _owner(host_folder)
        mode = 0o644

    tmp = f".hl-{secrets.token_hex(4)}-{name}"[:255]
    container = _helper(client, folder, ["sh", "-c", _PLACE, "sh", tmp, name], uid, gid)
    try:
        if not container.put_archive("/target", _tar_stream(tmp, size, source, uid, gid, mode)):
            raise DiskUsageError("the file helper refused the upload")
    except Exception:
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
        raise
    _run(container)

    st = os.lstat(host_target)
    audit.info("files: wrote %s (%s bytes) as %s", path, size, uid)
    return {"success": True, "path": path, "size": st.st_size, "modified": st.st_mtime}


def _mounted_by_container(client, path: str) -> str | None:
    for source, name in _container_mounts(client):
        if _under(source, path):
            return name
    return None


def rename(client, path: str, new_name: str, owner_uid: int | None) -> dict:
    path = normalize(path)
    new_name = (new_name or "").strip()
    if not new_name or "/" in new_name or new_name in (".", ".."):
        raise DiskUsageError("a plain new name is required")
    folder, name = posixpath.split(path)
    roots = write_roots(client, owner_uid)
    target = posixpath.join(folder, new_name)
    if path in roots:
        raise DiskUsageError(f"{path} is a root — renaming it would break what uses it")
    _require_writable(path, roots)
    _require_writable(target, roots)
    user = _mounted_by_container(client, path)
    if user:
        raise DiskUsageError(f"{user} is using {path} — stop it before renaming")
    host_folder = disk_usage._on_host(folder)
    if not os.path.lexists(os.path.join(host_folder, name)):
        raise DiskUsageError(f"{path} doesn't exist")
    if os.path.lexists(os.path.join(host_folder, new_name)):
        raise Conflict(f"{new_name} already exists")

    uid, gid = _owner(host_folder)
    _run(_helper(client, folder, ["mv", "-n", "--", name, new_name], uid, gid))
    if not os.path.lexists(os.path.join(host_folder, new_name)):
        raise DiskUsageError("the rename didn't happen")
    audit.info("files: renamed %s -> %s", path, new_name)
    return {"success": True, "path": target}


def make_folder(client, path: str, owner_uid: int | None) -> dict:
    path = normalize(path)
    folder, name = posixpath.split(path)
    if not name:
        raise DiskUsageError("a folder name is required")
    _require_writable(path, write_roots(client, owner_uid))
    host_folder = disk_usage._on_host(folder)
    if os.path.lexists(os.path.join(host_folder, name)):
        raise Conflict(f"{name} already exists")
    uid, gid = _owner(host_folder)
    _run(_helper(client, folder, ["mkdir", "--", name], uid, gid))
    audit.info("files: made folder %s", path)
    return {"success": True, "path": path}
