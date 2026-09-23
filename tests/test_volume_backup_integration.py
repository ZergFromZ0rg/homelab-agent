"""The whole mechanism against a real Docker daemon.

Everything else stubs the daemon, which is fine for policy and bookkeeping
and useless for the part that has actually gone wrong twice: a helper
container that starts but mounts the wrong thing, or writes somewhere the
host cannot see. This runs the real helper against a real volume and reads
the real archive back.

Skipped when there is no daemon, so it is free to keep in the suite and
worth running on a host that has one:

    ssh bigboy 'cd ~/homelab-agent && python3 -m pytest tests/test_volume_backup_integration.py -v'
"""

import json
import subprocess
import tarfile
import time
import uuid

import pytest

import config
import volume_backup

docker = pytest.importorskip("docker")


def daemon():
    try:
        client = docker.from_env()
        client.ping()
        return client
    except Exception:  # noqa: BLE001 - any failure means "no daemon here"
        return None


CLIENT = daemon()
needs_docker = pytest.mark.skipif(CLIENT is None, reason="no Docker daemon")

CONTENT = {"a.txt": b"hello volume", "sub/blob.bin": bytes(range(256)) * 40}


@pytest.fixture
def volume():
    """A real named volume with known contents."""
    name = f"hb-test-{uuid.uuid4().hex[:8]}"
    CLIENT.volumes.create(name)

    script = "mkdir -p /v/sub && printf 'hello volume' > /v/a.txt && " \
             "head -c 10240 /dev/zero | tr '\\0' 'x' > /v/sub/blob.bin"
    CLIENT.containers.run(
        "alpine", command=["sh", "-c", script],
        volumes={name: {"bind": "/v", "mode": "rw"}}, remove=True,
    )

    yield name

    try:
        CLIENT.volumes.get(name).remove(force=True)
    except Exception:  # noqa: BLE001 - best effort
        pass


@pytest.fixture
def destination(tmp_path, monkeypatch):
    """A real directory, with the policy pointed at it.

    ``resolve`` is patched rather than the environment because the real one
    maps a path inside the agent's container to its host path, and these
    tests run on the host with no container to map through.
    """
    out = tmp_path / "backups"
    out.mkdir()
    monkeypatch.setattr(volume_backup, "resolve", lambda c, d: (out, str(out)))
    monkeypatch.setattr(volume_backup, "ensure_dir", lambda c, d: (out, str(out)))
    return out


def wait_for(job_id, seconds=300):
    deadline = time.time() + seconds

    while time.time() < deadline:
        job = volume_backup.status(job_id)

        if job and job["state"] != "running":
            return job

        time.sleep(2)

    raise AssertionError("the backup never finished")


@needs_docker
def test_a_real_volume_backs_up_and_reads_back(volume, destination, monkeypatch):
    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "homelab-agent")
    volume_backup.reset()

    started = volume_backup.start(
        CLIENT, volume=volume, directory=str(destination)
    )
    job = wait_for(started["id"])

    assert job["state"] == "succeeded", job.get("error")

    archive = destination / job["archive"]
    assert archive.is_file(), list(destination.iterdir())

    # The contents, not just the size.
    with tarfile.open(archive) as tar:
        names = sorted(m.name for m in tar.getmembers() if m.isfile())
        assert names == ["./a.txt", "./sub/blob.bin"]
        assert tar.extractfile("./a.txt").read() == b"hello volume"

    # And the agent's own checker agrees.
    checked = volume_backup.verify(CLIENT, str(destination), job["archive"])
    assert checked["ok"] is True
    assert checked["files"] == 2


@needs_docker
def test_a_real_encrypted_backup_restores_with_gpg(volume, destination, monkeypatch):
    """The claim that matters for encryption: a restore needs gpg and the
    passphrase, and nothing from this repository."""
    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "homelab-agent")
    monkeypatch.setenv("BACKUP_PASSPHRASE", "correct horse battery staple")
    config.reload()
    volume_backup.reset()

    started = volume_backup.start(
        CLIENT, volume=volume, directory=str(destination)
    )
    job = wait_for(started["id"])

    assert job["state"] == "succeeded", job.get("error")
    assert job["archive"].endswith(".tar.gz.gpg")

    archive = destination / job["archive"]

    with pytest.raises(tarfile.ReadError):
        tarfile.open(archive)

    plain = subprocess.run(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
         "--passphrase", "correct horse battery staple", "-d", str(archive)],
        capture_output=True,
    )
    assert plain.returncode == 0, plain.stderr[:300]

    import io

    with tarfile.open(fileobj=io.BytesIO(plain.stdout), mode="r|gz") as tar:
        assert any(m.name == "./a.txt" for m in tar)

    assert volume_backup.verify(CLIENT, str(destination), job["archive"])["ok"] is True


@needs_docker
def test_a_corrupted_real_archive_is_caught(volume, destination, monkeypatch):
    """The check has to fail on a damaged archive, or it is theatre."""
    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "homelab-agent")
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    config.reload()
    volume_backup.reset()

    job = wait_for(volume_backup.start(
        CLIENT, volume=volume, directory=str(destination)
    )["id"])
    archive = destination / job["archive"]

    blob = bytearray(archive.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    archive.write_bytes(bytes(blob))

    assert volume_backup.verify(CLIENT, str(destination), job["archive"])["ok"] is False


@needs_docker
def test_a_truncated_real_archive_is_caught(volume, destination, monkeypatch):
    """The one that read as "intact, 0 files" until the drain was added."""
    monkeypatch.setenv("REBUILD_HELPER_IMAGE", "homelab-agent")
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    config.reload()
    volume_backup.reset()

    job = wait_for(volume_backup.start(
        CLIENT, volume=volume, directory=str(destination)
    )["id"])
    archive = destination / job["archive"]

    blob = archive.read_bytes()
    archive.write_bytes(blob[: len(blob) // 2])

    assert volume_backup.verify(CLIENT, str(destination), job["archive"])["ok"] is False
