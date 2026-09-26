"""Where the space went: per-folder disk usage for the dashboard's explorer.

``GET /disk/usage?path=/home/zerg`` lists a directory's children with the
space each one takes — folders summed over everything under them — biggest
first. It is what ``du -x --max-depth=1`` answers, readable from a browser.

How the numbers are counted, and why:

- **Space used, not file length.** ``st_blocks`` × 512, like ``du``: a
  sparse VM image or a half-written database file takes what it takes on
  disk, which is the question when a drive is filling.
- **One filesystem at a time**, like ``du -x``. A child on a different
  device (``/proc``, a USB disk under ``/mnt``, an sshfs mount of another
  host) is listed as a mount and not walked — walking ``/`` would otherwise
  descend into kernel pseudo-files or pull another machine's disk over the
  network. Open the mount to scan it on its own.
- **Hard links count once.** Docker's overlay layers are full of them.
- **Symlinks are never followed**; they are listed with their target.

A big tree takes a while, so a scan runs in the background: the first
request starts it and returns straight away, and repeat requests get the
same scan with its progress — each child's total fills in as its subtree
finishes. Finished scans are kept for ``CACHE_SECONDS``; ``refresh`` starts
over. At most ``MAX_CONCURRENT`` scans walk at once; the rest wait.

Everything is read through the agent's read-only ``/:/host`` mount (the one
backups already use). Nothing here writes.
"""

from __future__ import annotations

import os
import posixpath
import stat
import threading
import time

CACHE_SECONDS = 600
MAX_CONCURRENT = 2
MAX_ENTRIES = 300
PROGRESS_EVERY = 2000

_scans: dict[str, "Scan"] = {}
_lock = threading.Lock()
_slots = threading.Semaphore(MAX_CONCURRENT)


class DiskUsageError(ValueError):
    """A request refused before scanning; the message is shown as-is."""


def host_root() -> str:
    return os.getenv("HOST_ROOT", "/host").rstrip("/")


def normalize(path: str) -> str:
    if not path or not path.startswith("/"):
        raise DiskUsageError("path must be absolute")
    if ".." in path.split("/"):
        raise DiskUsageError("path must not contain '..'")
    return posixpath.normpath(path) or "/"


def _on_host(path: str) -> str:
    return host_root() + (path if path != "/" else "") or "/"


def _allocated(st: os.stat_result) -> int:
    blocks = getattr(st, "st_blocks", None)
    return blocks * 512 if blocks is not None else st.st_size


class Scan:
    def __init__(self, path: str):
        self.path = path
        self.state = "scanning"
        self.error: str | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.items = 0
        self.entries: list[dict] = []
        self._seen: set[tuple[int, int]] = set()
        self.thread: threading.Thread | None = None

    # -- counting -----------------------------------------------------------

    def _count_file(self, st: os.stat_result) -> int:
        if st.st_nlink > 1:
            key = (st.st_dev, st.st_ino)
            if key in self._seen:
                return 0
            self._seen.add(key)
        return _allocated(st)

    def _walk(self, entry: dict, root: str, device: int) -> None:
        total = entry["bytes"] or 0
        files = 0
        stack = [root]

        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for child in it:
                        self.items += 1
                        try:
                            st = child.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            if st.st_dev == device:
                                total += _allocated(st)
                                stack.append(child.path)
                        elif stat.S_ISLNK(st.st_mode):
                            continue
                        else:
                            files += 1
                            total += self._count_file(st)

                        if self.items % PROGRESS_EVERY == 0:
                            entry["bytes"] = total
                            entry["files"] = files
            except OSError:
                entry["unreadable"] = True
                continue

        entry["bytes"] = total
        entry["files"] = files
        entry["pending"] = False

    def run(self) -> None:
        with _slots:
            try:
                self._run()
                self.state = "done"
            except DiskUsageError as error:
                self.error = str(error)
                self.state = "error"
            except OSError as error:
                self.error = f"can't read {self.path}: {error.strerror or error}"
                self.state = "error"
            finally:
                self.finished_at = time.time()

    def _run(self) -> None:
        root = _on_host(self.path)
        try:
            top = os.lstat(root)
        except FileNotFoundError as error:
            raise DiskUsageError(f"{self.path} doesn't exist on this host") from error
        if not stat.S_ISDIR(top.st_mode):
            raise DiskUsageError(f"{self.path} isn't a directory")

        device = top.st_dev
        entries = []
        dirs = []

        with os.scandir(root) as it:
            children = list(it)

        for child in children:
            try:
                st = child.stat(follow_symlinks=False)
            except OSError:
                continue

            row = {
                "name": child.name,
                "path": posixpath.join(self.path, child.name),
                "modified": st.st_mtime,
                "bytes": None,
                "files": None,
                "pending": False,
            }

            if stat.S_ISLNK(st.st_mode):
                row["kind"] = "link"
                row["bytes"] = 0
                try:
                    row["target"] = os.readlink(child.path)
                except OSError:
                    pass
            elif stat.S_ISDIR(st.st_mode):
                if st.st_dev != device:
                    row["kind"] = "mount"
                else:
                    row["kind"] = "dir"
                    row["bytes"] = _allocated(st)
                    row["pending"] = True
                    dirs.append((row, child.path))
            elif stat.S_ISREG(st.st_mode):
                row["kind"] = "file"
                row["bytes"] = self._count_file(st)
            else:
                row["kind"] = "other"
                row["bytes"] = 0

            entries.append(row)

        self.entries = entries

        for row, path in dirs:
            self._walk(row, path, device)

    # -- reporting ----------------------------------------------------------

    def view(self) -> dict:
        rows = list(self.entries)
        rows.sort(key=lambda r: (-(r["bytes"] or 0), r["name"]))
        shown = rows[:MAX_ENTRIES]
        hidden = rows[MAX_ENTRIES:]

        total = sum(r["bytes"] or 0 for r in rows)
        parent = posixpath.dirname(self.path) if self.path != "/" else None

        return {
            "path": self.path,
            "parent": parent,
            "state": self.state,
            "error": self.error,
            "total_bytes": total,
            "items_scanned": self.items,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "entries": shown,
            "more": {
                "count": len(hidden),
                "bytes": sum(r["bytes"] or 0 for r in hidden),
            }
            if hidden
            else None,
        }


def usage(path: str, *, refresh: bool = False, wait: bool = False) -> dict:
    """The scan for ``path`` — cached, in progress, or freshly started."""
    path = normalize(path)
    now = time.time()

    with _lock:
        scan = _scans.get(path)
        stale = (
            scan is None
            or refresh and scan.state != "scanning"
            or scan.state != "scanning"
            and scan.finished_at is not None
            and now - scan.finished_at > CACHE_SECONDS
        )
        if stale:
            scan = Scan(path)
            _scans[path] = scan
            scan.thread = threading.Thread(target=scan.run, daemon=True)
            scan.thread.start()

    if wait and scan.thread is not None:
        scan.thread.join()

    return scan.view()


def forget() -> None:
    with _lock:
        _scans.clear()
