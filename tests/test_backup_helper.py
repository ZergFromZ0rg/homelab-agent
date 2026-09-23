"""The helper that actually makes the archive.

It normally runs inside a throwaway container with a volume bound at
``/src``, but nothing in it is Docker-specific — point it at a directory
and it does the same thing, which is what these tests do.
"""

import hashlib
import io
import os
import json
import subprocess
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

HELPER = "backup_helper.py"


def make_volume(path):
    (path / "sub").mkdir(parents=True)
    (path / "a.txt").write_text("hello volume")
    (path / "sub" / "blob.bin").write_bytes(bytes(range(256)) * 400)
    (path / "link.txt").symlink_to("a.txt")
    return path


def run_helper(src, *, dest=None, env=None, name="test.tar.gz"):
    full = {
        "BACKUP_SRC": str(src),
        "BACKUP_NAME": name,
        **({"BACKUP_DEST": str(dest)} if dest else {}),
        **(env or {}),
    }

    done = subprocess.run(
        [sys.executable, HELPER],
        # The real PATH, not a minimal one: gpg lives wherever the machine
        # running these tests put it (/opt/homebrew on a Mac, /usr/bin in
        # the container), and a stripped PATH only tests that.
        capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **full},
    )

    try:
        report = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report = {"error": done.stdout + done.stderr}

    return done.returncode, report


def test_it_writes_a_readable_archive(tmp_path):
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    code, report = run_helper(src, dest=dest)

    assert code == 0, report
    assert report["files"] == 2
    assert report["sha256"]

    with tarfile.open(dest / "test.tar.gz") as tar:
        names = sorted(m.name for m in tar.getmembers())
        assert names == [".", "./a.txt", "./link.txt", "./sub", "./sub/blob.bin"]
        assert tar.extractfile("./a.txt").read() == b"hello volume"


def test_the_archive_restores_to_the_same_bytes(tmp_path):
    """The only property that matters. Everything else is bookkeeping."""
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()
    restored = tmp_path / "restored"
    restored.mkdir()

    code, _ = run_helper(src, dest=dest)
    assert code == 0

    with tarfile.open(dest / "test.tar.gz") as tar:
        tar.extractall(restored, filter="tar")

    assert (restored / "a.txt").read_text() == "hello volume"
    assert (restored / "sub" / "blob.bin").read_bytes() == (
        src / "sub" / "blob.bin"
    ).read_bytes()
    assert (restored / "link.txt").is_symlink()


def test_two_runs_over_unchanged_data_agree(tmp_path):
    """gzip stamps its header with the time by default, which would make
    every archive of identical data a different archive. The checksum is
    only worth reporting if it means something."""
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    _, first = run_helper(src, dest=dest, name="one.tar.gz")
    _, second = run_helper(src, dest=dest, name="two.tar.gz")

    assert first["sha256"] == second["sha256"]


def test_nothing_partial_survives_a_finished_run(tmp_path):
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    run_helper(src, dest=dest)

    assert [p.name for p in dest.iterdir()] == ["test.tar.gz"]


def test_a_missing_source_is_an_error_not_an_empty_archive(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()

    code, report = run_helper(tmp_path / "nope", dest=dest)

    assert code == 2
    assert "not mounted" in report["error"]
    assert list(dest.iterdir()) == []


# ---- streaming to another node -------------------------------------------


class Receiver:
    """Stands in for the destination agent's ``POST /backup/receive``."""

    def __init__(self, status=200, corrupt=False):
        self.status = status
        self.corrupt = corrupt
        self.seen = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                digest = hashlib.sha256()
                total = 0

                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    while True:
                        size = int(self.rfile.readline().split(b";")[0], 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        block = self.rfile.read(size)
                        self.rfile.readline()
                        digest.update(block)
                        total += len(block)
                else:
                    length = int(self.headers.get("Content-Length", 0))
                    block = self.rfile.read(length)
                    digest.update(block)
                    total = length

                outer.seen = {
                    "encoding": self.headers.get("Transfer-Encoding", "length"),
                    "dir": self.headers.get("X-Backup-Dir"),
                    "name": self.headers.get("X-Backup-Name"),
                    "token": self.headers.get("X-Agent-Token"),
                    "bytes": total,
                }

                sha = digest.hexdigest()
                if outer.corrupt:
                    sha = "0" * 64

                body = json.dumps(
                    {"bytes": total, "sha256": sha} if outer.status < 400
                    else {"detail": "not under a backup directory"}
                ).encode()

                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()


@pytest.fixture
def volume(tmp_path):
    return make_volume(tmp_path / "src")


def test_it_streams_to_another_agent_without_staging_the_archive(volume):
    with Receiver() as receiver:
        code, report = run_helper(volume, env={
            "BACKUP_DEST_URL": receiver.url,
            "BACKUP_DEST_DIR": "/backups/bigboy",
            "BACKUP_TOKEN": "sekret",
        })

    assert code == 0, report
    assert receiver.seen["encoding"].lower() == "chunked", (
        "a staged archive would arrive with a Content-Length"
    )
    assert receiver.seen["dir"] == "/backups/bigboy"
    assert receiver.seen["token"] == "sekret"
    assert receiver.seen["bytes"] == report["bytes"]


def test_the_streamed_archive_is_the_same_one_as_the_local_archive(tmp_path, volume):
    """Same bytes either way, which is what makes the checksum comparison
    at the end of a remote run meaningful."""
    dest = tmp_path / "dest"
    dest.mkdir()

    _, local = run_helper(volume, dest=dest)

    with Receiver() as receiver:
        _, streamed = run_helper(volume, env={
            "BACKUP_DEST_URL": receiver.url, "BACKUP_DEST_DIR": "/backups",
        })

    assert local["sha256"] == streamed["sha256"]


def test_a_checksum_disagreement_fails_the_run(volume):
    """What landed is not what was sent. Better to hear it now than at a
    restore."""
    with Receiver(corrupt=True) as receiver:
        code, report = run_helper(volume, env={
            "BACKUP_DEST_URL": receiver.url, "BACKUP_DEST_DIR": "/backups",
        })

    assert code == 1
    assert "checksum mismatch" in report["error"]


def test_a_refusal_is_reported_with_the_reason(volume):
    with Receiver(status=400) as receiver:
        code, report = run_helper(volume, env={
            "BACKUP_DEST_URL": receiver.url, "BACKUP_DEST_DIR": "/etc",
        })

    assert code == 1
    assert "not under a backup directory" in report["error"]


def test_an_unreachable_agent_is_reported(volume):
    code, report = run_helper(volume, env={
        "BACKUP_DEST_URL": "http://127.0.0.1:1", "BACKUP_DEST_DIR": "/backups",
    })

    assert code == 1
    assert report["error"]


# ---- encryption -----------------------------------------------------------

import shutil

needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")

PASSPHRASE = "correct horse battery staple"


@needs_gpg
def test_an_encrypted_archive_is_not_readable_as_a_tar(tmp_path):
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    code, report = run_helper(
        src, dest=dest, name="test.tar.gz.gpg",
        env={"BACKUP_PASSPHRASE": PASSPHRASE},
    )

    assert code == 0, report
    assert report["encrypted"] is True

    with pytest.raises(tarfile.ReadError):
        tarfile.open(dest / "test.tar.gz.gpg")


@needs_gpg
def test_an_encrypted_archive_restores_with_gpg_and_tar_alone(tmp_path):
    """The reason for using a standard format instead of rolling one: a
    restore needs gpg and the passphrase and nothing from this repository.
    A backup whose only reader is the tool that made it is a hostage."""
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()
    restored = tmp_path / "restored"
    restored.mkdir()

    run_helper(src, dest=dest, name="test.tar.gz.gpg",
               env={"BACKUP_PASSPHRASE": PASSPHRASE})

    plain = subprocess.run(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
         "--passphrase", PASSPHRASE, "-d", str(dest / "test.tar.gz.gpg")],
        capture_output=True,
    )
    assert plain.returncode == 0, plain.stderr[:300]

    with tarfile.open(fileobj=io.BytesIO(plain.stdout), mode="r|gz") as tar:
        tar.extractall(restored, filter="tar")

    assert (restored / "a.txt").read_text() == "hello volume"
    assert (restored / "sub" / "blob.bin").read_bytes() == (
        src / "sub" / "blob.bin"
    ).read_bytes()


@needs_gpg
def test_the_wrong_passphrase_does_not_open_it(tmp_path):
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    run_helper(src, dest=dest, name="test.tar.gz.gpg",
               env={"BACKUP_PASSPHRASE": PASSPHRASE})

    out = subprocess.run(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
         "--passphrase", "wrong", "-d", str(dest / "test.tar.gz.gpg")],
        capture_output=True,
    )

    assert out.returncode != 0


@needs_gpg
def test_encryption_streams_to_another_agent_too(tmp_path):
    src = make_volume(tmp_path / "src")

    with Receiver() as receiver:
        code, report = run_helper(src, env={
            "BACKUP_DEST_URL": receiver.url, "BACKUP_DEST_DIR": "/backups",
            "BACKUP_PASSPHRASE": PASSPHRASE,
        }, name="test.tar.gz.gpg")

    assert code == 0, report
    assert report["encrypted"] is True
    assert receiver.seen["encoding"].lower() == "chunked", (
        "still streamed — encryption must not mean staging the whole archive"
    )
    assert receiver.seen["bytes"] == report["bytes"]


@needs_gpg
def test_a_bad_passphrase_setup_reports_gpgs_own_error(tmp_path):
    """gpg's message is the only one that says what went wrong; a broken
    pipe from the writer thread would hide it."""
    src = make_volume(tmp_path / "src")
    dest = tmp_path / "dest"
    dest.mkdir()

    code, report = run_helper(
        src, dest=dest, name="test.tar.gz.gpg",
        env={"BACKUP_PASSPHRASE": PASSPHRASE, "GNUPGHOME": "/nonexistent/nope"},
    )

    if code != 0:
        assert "gpg" in report["error"].lower()
        assert "broken pipe" not in report["error"].lower()
