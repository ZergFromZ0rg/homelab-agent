"""Runs inside a throwaway container to back one Docker volume up.

The agent can't do this itself. It has no way to mount a volume into its
own already-running container, and the whole point is to read a volume it
doesn't otherwise touch. So the agent starts a container with the volume
bound read-only at ``/src`` and this script as its command — the same
throwaway-helper shape ``rebuild.py`` uses, for the same reason.

Everything here is standard library on purpose. This runs in the agent's
own image, which carries git, the Docker CLI and the Compose plugin but
deliberately purges curl; a backup must not depend on anything a future
Dockerfile change might drop.

Mounts
    /src    the volume, read-only
    /dest   the destination directory, when it is on this host

Environment
    BACKUP_NAME       the archive's filename
    BACKUP_DEST_URL   a *remote* agent's base url, when the destination is
                      on another node. Mutually exclusive with /dest.
    BACKUP_DEST_DIR   the directory to ask that agent to write into
    BACKUP_TOKEN      that agent's AGENT_TOKEN, if it sets one

Output
    one line of JSON on stdout. The archive itself never goes to stdout —
    the agent reads this container's logs to find out how it went, and
    binary down that channel would arrive mangled by Docker's stream
    framing.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import queue
import stat
import sys
import tarfile
import threading
import time
import urllib.parse

# The mount points the agent sets up. Overridable only so the tests can
# exercise this against a temporary directory instead of a container.
SRC = os.environ.get("BACKUP_SRC", "/src")
DEST = os.environ.get("BACKUP_DEST", "/dest")

# Big enough that the queue isn't the bottleneck, small enough that a
# stalled upload can't grow the helper's memory without bound: the tar
# thread blocks once this many chunks are waiting.
QUEUE_DEPTH = 16
CHUNK_BYTES = 1024 * 1024


class Counter:
    """What went into the archive, and what came out of the gzip."""

    def __init__(self):
        self.files = 0
        self.skipped = 0
        self.raw_bytes = 0
        self.archive_bytes = 0
        self.digest = hashlib.sha256()


def _tar_filter(info: tarfile.TarInfo, counts: Counter):
    """Sockets can't be restored and don't belong in an archive; tar stores
    a useless zero-length entry for them. Everything else goes in as-is,
    ownership included, because a restore wants the volume back exactly as
    it was."""
    if stat.S_ISSOCK(info.mode) or info.type not in (
        tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
        tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
    ):
        counts.skipped += 1
        return None

    if info.isfile():
        counts.files += 1
        counts.raw_bytes += info.size

    return info


class _Sink:
    """A write-only file object that measures and hashes on the way past.

    gzip writes here; where the bytes actually land is whatever ``emit``
    does with them.
    """

    def __init__(self, emit, counts: Counter):
        self._emit = emit
        self._counts = counts

    def write(self, data) -> int:
        block = bytes(data)
        if block:
            self._counts.archive_bytes += len(block)
            self._counts.digest.update(block)
            self._emit(block)
        return len(data)

    def flush(self) -> None:
        pass


def _write_archive(emit, counts: Counter) -> None:
    """Tar ``/src`` through gzip into ``emit``.

    ``mtime=0`` on the gzip header so two runs over unchanged data differ
    only where the data differs — it makes an archive's checksum mean
    something. ``w|`` is tar's stream mode: no seeking back, which is what
    lets this work against a pipe or a socket at all.
    """
    sink = _Sink(emit, counts)
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0)

    try:
        with tarfile.open(mode="w|", fileobj=gz, format=tarfile.PAX_FORMAT) as tar:
            tar.add(SRC, arcname=".", filter=lambda i: _tar_filter(i, counts))
    finally:
        gz.close()


def _to_file(path: str, counts: Counter) -> None:
    partial = f"{path}.part"

    with open(partial, "wb") as handle:
        _write_archive(handle.write, counts)
        handle.flush()
        os.fsync(handle.fileno())

    # Rename last, so a crashed or killed helper leaves a .part behind
    # rather than a truncated archive that looks complete.
    os.replace(partial, path)


class _Chunks:
    """Turns the tar, which pushes, into an iterable, which pulls.

    ``http.client`` takes an iterable body and sends it chunked, so the
    archive never has to exist anywhere in full — not in this container's
    memory and not on its disk. The tar runs in its own thread and blocks
    when the reader falls behind.
    """

    def __init__(self):
        self._queue: queue.Queue = queue.Queue(QUEUE_DEPTH)
        self._error: BaseException | None = None

    def feed(self, counts: Counter) -> None:
        try:
            _write_archive(self._queue.put, counts)
        except BaseException as error:  # noqa: BLE001 - re-raised in the reader
            self._error = error
        finally:
            self._queue.put(None)

    def __iter__(self):
        while True:
            chunk = self._queue.get()

            if chunk is None:
                break

            yield chunk

        if self._error is not None:
            raise self._error


def _to_agent(base_url: str, directory: str, name: str, token: str,
              counts: Counter) -> dict:
    url = urllib.parse.urlparse(base_url.rstrip("/") + "/backup/receive")
    chunks = _Chunks()

    thread = threading.Thread(target=chunks.feed, args=(counts,), daemon=True)
    thread.start()

    connection = (
        http.client.HTTPSConnection if url.scheme == "https"
        else http.client.HTTPConnection
    )(url.netloc, timeout=600)

    headers = {
        "Content-Type": "application/octet-stream",
        "X-Backup-Dir": directory,
        "X-Backup-Name": name,
    }

    if token:
        headers["X-Agent-Token"] = token

    connection.request("POST", url.path, body=iter(chunks), headers=headers)
    response = connection.getresponse()
    body = response.read().decode("utf-8", "replace")
    connection.close()
    thread.join(timeout=30)

    if response.status >= 400:
        try:
            detail = json.loads(body).get("detail") or body
        except ValueError:
            detail = body

        raise RuntimeError(
            f"the agent at {base_url} refused the archive "
            f"({response.status}): {str(detail)[:300]}"
        )

    try:
        return json.loads(body)
    except ValueError:
        return {}


def main() -> int:
    name = os.environ.get("BACKUP_NAME", "").strip()
    dest_url = os.environ.get("BACKUP_DEST_URL", "").strip()
    dest_dir = os.environ.get("BACKUP_DEST_DIR", "").strip()
    token = os.environ.get("BACKUP_TOKEN", "").strip()

    if not name:
        print(json.dumps({"error": "BACKUP_NAME is required"}))
        return 2

    if not os.path.isdir(SRC):
        print(json.dumps({"error": f"{SRC} is not mounted"}))
        return 2

    counts = Counter()
    started = time.time()
    remote = None

    try:
        if dest_url:
            remote = _to_agent(dest_url, dest_dir, name, token, counts)
        else:
            _to_file(os.path.join(DEST, name), counts)

    except Exception as error:  # noqa: BLE001 - the message is the product
        print(json.dumps({"error": str(error)[:500]}))
        return 1

    result = {
        "name": name,
        "files": counts.files,
        "skipped": counts.skipped,
        "raw_bytes": counts.raw_bytes,
        "bytes": counts.archive_bytes,
        "sha256": counts.digest.hexdigest(),
        "seconds": round(time.time() - started, 1),
        "destination": dest_url or DEST,
    }

    # The receiving agent hashed the bytes it actually stored. If that
    # doesn't match what we sent, the archive on disk is not the archive
    # this helper built, and saying so now beats finding out at restore.
    if remote and remote.get("sha256") and remote["sha256"] != result["sha256"]:
        print(json.dumps({
            **result,
            "error": (
                "checksum mismatch: sent "
                f"{result['sha256'][:12]}, stored {remote['sha256'][:12]}"
            ),
        }))
        return 1

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
