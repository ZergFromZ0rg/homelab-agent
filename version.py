"""What this agent is running, and whether that's current.

A fleet that can rebuild itself needs to know what it would be rebuilding
*from*. Three facts answer that, and they're all cheap:

- when the running image was built (Docker knows);
- what the checkout on disk is at (its HEAD);
- what the remote is at (one ``git ls-remote``).

From those:

``needs_rebuild``
    The checkout has moved on since the image was built — somebody pulled
    and didn't rebuild. Comparing the *image's build time* to the *commit
    date* rather than comparing shas is deliberate: it stays correct when
    a container is restarted without being rebuilt, which comparing a sha
    baked in at build time would not.

``behind_remote``
    The remote has commits this checkout doesn't. A rebuild will pull them.

Both are advisory. Nothing here changes anything.

  VERSION_CACHE  seconds to reuse a remote check (default 300). The ls-
                 remote is the only part that touches the network.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

import rebuild
from log import log

REMOTE_TIMEOUT = 15


def cache_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("VERSION_CACHE", "300")))
    except ValueError:
        return 300.0


def _git(args: list[str], cwd: str, timeout: int = 10) -> str | None:
    """Run git in a checkout we don't own. ``safe.directory`` for the same
    reason the rebuild helper needs it: this runs as root against someone
    else's repo, and git refuses that by default."""
    try:
        done = subprocess.run(
            ["git", "-c", f"safe.directory={cwd}", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        log.debug("git %s failed in %s: %s", args[0], cwd, error)
        return None

    if done.returncode != 0:
        log.debug("git %s in %s: %s", args[0], cwd, (done.stderr or "").strip()[:200])
        return None

    return done.stdout.strip() or None


def source_info(path: str) -> dict | None:
    """HEAD of the checkout the agent was built from."""
    if not Path(path, ".git").exists():
        return None

    head = _git(["log", "-1", "--format=%H %ct"], path)
    if not head:
        return None

    sha, _, committed = head.partition(" ")

    try:
        committed_at = float(committed)
    except ValueError:
        committed_at = None

    return {
        "sha": sha,
        "short": sha[:7],
        "committed_at": committed_at,
        "branch": _git(["rev-parse", "--abbrev-ref", "HEAD"], path),
    }


def remote_sha(path: str, branch: str | None, url: str | None = None) -> str | None:
    """What the remote's branch is at. One network call, cached by the
    caller.

    Asks the url by name rather than "origin" for the same reason the
    rebuild helper does: a remote configured for ssh push can still be
    read over https from in here, and this is an unauthenticated read of a
    public repo either way.
    """
    ref = branch or "HEAD"
    target = url or "origin"
    out = _git(["ls-remote", target, ref], path, timeout=REMOTE_TIMEOUT)

    if not out:
        return None

    return out.split()[0] or None


def image_created(client, container_id: str) -> float | None:
    """When the running image was built, as an epoch."""
    try:
        container = client.containers.get(container_id)
        created = container.image.attrs.get("Created")
    except Exception as error:  # noqa: BLE001 - docker-py raises broadly
        log.debug("could not read this agent's image: %s", error)
        return None

    if not created:
        return None

    # "2026-09-21T20:27:51.775288778Z" — more precision than fromisoformat
    # accepts on some versions, and the sub-second part doesn't matter.
    text = created.replace("Z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        offset = tail[-6:] if "+" in tail or "-" in tail else "+00:00"
        text = head + offset

    try:
        from datetime import datetime

        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


_cache: dict = {"at": 0.0, "remote": None}
_lock = threading.Lock()


def report(client, working_dir: str | None, container_id: str = "") -> dict:
    """The version block served at ``GET /`` and ``GET /version``."""
    info = {
        "source": None,
        "remote_sha": None,
        "fetch_url": None,
        "image_created": None,
        "needs_rebuild": False,
        "behind_remote": False,
    }

    if not working_dir:
        return info

    # The url the check will actually use — https even when the remote is
    # configured for ssh push, since this container has no keys and needs
    # none for a public repo.
    info["fetch_url"] = rebuild.https_equivalent(
        rebuild.origin_url(Path(working_dir) / ".git")
    )

    info["image_created"] = image_created(client, container_id)
    source = source_info(working_dir)
    info["source"] = source

    if not source:
        return info

    # A pull without a rebuild: the checkout carries a commit the running
    # image can't contain, because it was made after the image was built.
    if info["image_created"] and source["committed_at"]:
        info["needs_rebuild"] = source["committed_at"] > info["image_created"]

    now = time.time()
    with _lock:
        fresh = now - _cache["at"] < cache_seconds()
        cached = _cache["remote"]

    if fresh:
        info["remote_sha"] = cached
    else:
        sha = remote_sha(working_dir, source["branch"], info["fetch_url"])
        with _lock:
            _cache.update(at=now, remote=sha)
        info["remote_sha"] = sha

    if info["remote_sha"]:
        info["behind_remote"] = info["remote_sha"] != source["sha"]

    return info


def reset_cache() -> None:
    with _lock:
        _cache.update(at=0.0, remote=None)
