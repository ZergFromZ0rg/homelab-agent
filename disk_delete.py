"""Delete a file or folder from the disk explorer.

``POST /disk/delete {"path": "/home/zerg/clips/old.mp4"}``. Destructive and
unrecoverable, so the checks are strict and all happen before anything runs:

- **Never a system directory** or anything under one (``/etc``, ``/usr``,
  ``/boot``, ``/var/lib/docker`` …) — ``PROTECTED`` below.
- **Never a top-level directory** (``/home``, ``/mnt``, ``/srv`` …). Clear
  what's inside instead; removing the directory itself is never the fix
  for a full disk and can break the host.
- **Never a mount point.** Deleting one would empty another disk, or another
  machine over sshfs.
- **Never a folder a running container has mounted**, or one containing
  such a folder — the service would lose its data mid-run. Files *inside* a
  mounted folder (a clip in a media library) are fine; that is most of what
  this is for.

The agent reads the host through a read-only mount and keeps it that way.
The delete runs the way backups write: Docker starts a throwaway helper
container with just the *parent* folder mounted writable and runs ``rm``
there, with the name as a plain argument (no shell).
"""

from __future__ import annotations

import os
import posixpath
import stat

import disk_usage
import rebuild
from disk_usage import DiskUsageError, normalize
from log import audit

PROTECTED = (
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
    "/proc", "/root", "/run", "/sbin", "/snap", "/sys", "/usr",
    "/var/lib/docker", "/var/lib/containerd", "/var/lib/dpkg", "/var/lib/apt",
    "/var/lib/systemd", "/var/run",
)

TIMEOUT_SECONDS = 900


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _container_mounts(client) -> list[tuple[str, str]]:
    """(host path, container name) for every bind mount of a running container."""
    mounts = []
    for container in client.containers.list():
        for m in container.attrs.get("Mounts") or []:
            source = m.get("Source")
            if m.get("Type") == "bind" and source:
                mounts.append((source.rstrip("/") or "/", container.name))
    return mounts


def check(client, path: str) -> dict:
    """What would be deleted, or DiskUsageError saying why it won't be."""
    path = normalize(path)

    if path.count("/") < 2:
        raise DiskUsageError(
            f"{path} is a top-level directory — delete what's inside it instead"
        )
    for root in PROTECTED:
        if _under(path, root):
            raise DiskUsageError(f"{path} is part of the operating system ({root})")

    host_path = disk_usage._on_host(path)
    try:
        st = os.lstat(host_path)
    except FileNotFoundError as error:
        raise DiskUsageError(f"{path} doesn't exist") from error

    parent_st = os.lstat(os.path.dirname(host_path))
    if stat.S_ISDIR(st.st_mode) and st.st_dev != parent_st.st_dev:
        raise DiskUsageError(f"{path} is a mount point — unmount it instead")

    for source, name in _container_mounts(client):
        if _under(source, path):
            raise DiskUsageError(
                f"{name} is using {source} — stop that container before deleting it"
            )

    return {
        "path": path,
        "kind": "dir" if stat.S_ISDIR(st.st_mode) else "file",
    }


def delete(client, path: str) -> dict:
    target = check(client, path)
    path = target["path"]
    parent, name = posixpath.split(path)

    freed = disk_usage.known_bytes(path)

    container = None
    try:
        container = client.containers.run(
            rebuild.helper_image(client),
            command=["rm", "-rf", "--one-file-system", "--", f"/target/{name}"],
            detach=True,
            volumes={parent: {"bind": "/target", "mode": "rw"}},
            labels={"homelab-agent-delete": path},
            network_disabled=True,
        )
        result = container.wait(timeout=TIMEOUT_SECONDS)
        code = result.get("StatusCode", 1) if isinstance(result, dict) else 1
        output = container.logs().decode("utf-8", "replace").strip()
    except Exception as error:  # noqa: BLE001 - reported to the user as-is
        audit.warning("delete %s failed to run: %s", path, error)
        raise DiskUsageError(f"the delete helper failed to run: {error}") from error
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001 - best effort
                pass

    if code != 0:
        audit.warning("delete %s exited %s: %s", path, code, output[-300:])
        raise DiskUsageError(output[-300:] or f"rm exited {code}")

    disk_usage.forget_path(path, freed)
    audit.info("deleted %s (%s bytes)", path, freed)
    return {"success": True, "path": path, "freed_bytes": freed}
