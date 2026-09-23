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
    BACKUP_PASSPHRASE when set, the archive is encrypted with gpg before it
                      is written or sent. Symmetric, AES256, standard
                      OpenPGP: a restore needs gpg and the passphrase, and
                      nothing from this repository. That is the point — a
                      backup whose only reader is the tool that made it is
                      a hostage, not a backup.
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
import subprocess
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


def gpg_command(passphrase_fd: int) -> list[str]:
    """Symmetric AES256, passphrase down a file descriptor.

    The fd number is passed in rather than fixed: ``os.pipe()`` hands back
    whatever numbers are free and ``pass_fds`` keeps those numbers in the
    child, so hardcoding ``3`` means gpg waits on a descriptor nobody is
    writing to.
    """
    return [
        "gpg", "--batch", "--yes", "--quiet", "--no-tty",
        "--pinentry-mode", "loopback", "--passphrase-fd", str(passphrase_fd),
        "--symmetric", "--cipher-algo", "AES256",
        # Already gzipped. Compressing ciphertext-to-be twice buys nothing
        # and costs real time on a slow box.
        "--compress-algo", "none",
    ]


def _write_archive(emit, counts: Counter, *, count_output: bool = True) -> None:
    """Tar ``/src`` through gzip into ``emit``.

    ``mtime=0`` on the gzip header so two runs over unchanged data differ
    only where the data differs — it makes an archive's checksum mean
    something. ``w|`` is tar's stream mode: no seeking back, which is what
    lets this work against a pipe or a socket at all.

    ``count_output`` is off when something downstream (gpg) will produce
    the bytes that actually land, since those are the ones worth measuring
    and hashing.
    """
    sink = _Sink(emit, counts) if count_output else _Passthrough(emit)
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0)

    try:
        with tarfile.open(mode="w|", fileobj=gz, format=tarfile.PAX_FORMAT) as tar:
            tar.add(SRC, arcname=".", filter=lambda i: _tar_filter(i, counts))
    finally:
        gz.close()


class _Passthrough:
    """A write-only file object that just forwards."""

    def __init__(self, emit):
        self._emit = emit

    def write(self, data) -> int:
        block = bytes(data)
        if block:
            self._emit(block)
        return len(data)

    def flush(self) -> None:
        pass


def _produce(emit, counts: Counter, passphrase: str) -> None:
    """The bytes that land, plain or encrypted.

    With a passphrase the tar goes into gpg's stdin on a thread while this
    reads its stdout, because a pipe in both directions fills up and
    deadlocks if only one end is being served.
    """
    if not passphrase:
        _write_archive(emit, counts)
        return

    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        gpg_command(read_fd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, pass_fds=(read_fd,),
    )

    # Down a pipe, not in argv: anything on the command line is readable by
    # every process on the host for as long as gpg runs.
    with os.fdopen(write_fd, "wb") as handle:
        handle.write(passphrase.encode() + b"\n")

    os.close(read_fd)

    failure: list[BaseException] = []

    def feed():
        try:
            _write_archive(process.stdin.write, counts, count_output=False)
        except BaseException as error:  # noqa: BLE001 - re-raised below
            failure.append(error)
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass

    thread = threading.Thread(target=feed, daemon=True)
    thread.start()

    sink = _Sink(emit, counts)

    while True:
        chunk = process.stdout.read(CHUNK_BYTES)

        if not chunk:
            break

        sink.write(chunk)

    process.stdout.close()
    code = process.wait()
    stderr = (process.stderr.read() or b"").decode("utf-8", "replace").strip()
    process.stderr.close()
    thread.join(timeout=30)

    # gpg's own complaint first. When it dies the writer thread sees a
    # broken pipe, and reporting that instead would hide the only message
    # that says what went wrong.
    if code != 0:
        raise RuntimeError(f"gpg failed ({code}): {stderr[:300]}")

    if failure:
        raise failure[0]


def _to_file(path: str, counts: Counter, passphrase: str) -> None:
    partial = f"{path}.part"

    with open(partial, "wb") as handle:
        _produce(handle.write, counts, passphrase)
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

    def feed(self, counts: Counter, passphrase: str = "") -> None:
        try:
            _produce(self._queue.put, counts, passphrase)
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
              counts: Counter, passphrase: str = "") -> dict:
    url = urllib.parse.urlparse(base_url.rstrip("/") + "/backup/receive")
    chunks = _Chunks()

    thread = threading.Thread(
        target=chunks.feed, args=(counts, passphrase), daemon=True
    )
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
    passphrase = os.environ.get("BACKUP_PASSPHRASE", "")

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
            remote = _to_agent(dest_url, dest_dir, name, token, counts, passphrase)
        else:
            _to_file(os.path.join(DEST, name), counts, passphrase)

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
        "encrypted": bool(passphrase),
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
