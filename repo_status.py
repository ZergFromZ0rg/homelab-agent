"""Is the checkout behind a project's containers current with GitHub?

A container Compose started from a git checkout has a source: the repo it was
built from. This module reads that checkout (its branch, its commit, whether it
has uncommitted changes) and asks GitHub what the branch is at, so the dashboard
can say "ai-librarian has new commits" and offer a pull and redeploy — the
rebuild route does the pulling, see rebuild.py.

Everything here is read-only and none of it blocks ``GET /containers``: a
background thread refreshes what each tracked checkout looks like, and the
snapshot only reads the last answer. The host is mounted read-only (``/host``),
and git runs with optional locks off, so even a git that wanted to refresh an
index cannot touch the user's checkout.

  REPO_LOCAL_SECONDS   how often to re-read a checkout (default 45).
  REPO_REMOTE_SECONDS  how often to ask GitHub (default 300). One
                       ``git ls-remote`` per repo and branch, shared by every
                       project that points at it.

The state of a checkout against its remote:

  up_to_date  the remote branch is at the commit that is checked out
  behind      the remote has commits the checkout doesn't — a pull brings them
  ahead       the checkout has commits the remote doesn't (not pushed yet)
  unknown     the remote couldn't be asked (private repo, no network) or the
              checkout is on no branch
  checking    first sight; the thread hasn't answered yet
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time

from log import log

# Reading a private repo over https would otherwise wait for a username on a
# terminal that isn't there; this makes it fail at once.
os.environ.setdefault("GIT_TERMINAL_PROMPT", "0")
os.environ.setdefault("GIT_OPTIONAL_LOCKS", "0")

LOCAL_TIMEOUT = 10
REMOTE_TIMEOUT = 15
FORGET_AFTER = 600  # stop tracking a checkout nobody has asked about this long
TICK = 5

_GITHUB = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", re.IGNORECASE)


def local_seconds() -> float:
    try:
        return max(5.0, float(os.getenv("REPO_LOCAL_SECONDS", "45")))
    except ValueError:
        return 45.0


def remote_seconds() -> float:
    try:
        return max(30.0, float(os.getenv("REPO_REMOTE_SECONDS", "300")))
    except ValueError:
        return 300.0


def github_repo(url: str | None) -> tuple[str, str] | None:
    """(owner, name) of a GitHub remote, whichever way it is written."""
    match = _GITHUB.search(url or "")
    return (match.group(1), match.group(2)) if match else None


def _run(args: list[str], cwd: str, timeout: int = LOCAL_TIMEOUT) -> tuple[int | None, str]:
    """git in a checkout we don't own: ``safe.directory`` because this runs as
    root against someone else's repo. -> (exit code, stdout); the code is None
    when git could not be run at all."""
    try:
        done = subprocess.run(
            ["git", "--no-optional-locks", "-c", f"safe.directory={cwd}", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        log.debug("git %s failed in %s: %s", args[0], cwd, error)
        return None, ""

    if done.returncode != 0:
        log.debug("git %s in %s: %s", args[0], cwd, (done.stderr or "").strip()[:200])

    return done.returncode, (done.stdout or "").strip()


def local_info(path: str) -> dict | None:
    """The checkout as it is on disk, or None if git can't read it."""
    code, out = _run(["log", "-1", "--format=%H%x1f%ct%x1f%s"], path)
    if code != 0 or not out:
        return None

    sha, _, rest = out.partition("\x1f")
    committed, _, subject = rest.partition("\x1f")

    # Exits 1 with no output on a detached HEAD.
    _, branch = _run(["symbolic-ref", "--short", "-q", "HEAD"], path)

    # Tracked files only: it is the "will a pull be refused" question, and
    # untracked files are slow to scan and rarely in the way.
    status_code, status = _run(["status", "--porcelain", "--untracked-files=no"], path)

    try:
        committed_at = float(committed)
    except ValueError:
        committed_at = None

    return {
        "sha": sha,
        "short": sha[:7],
        "branch": branch or None,
        "subject": subject[:120],
        "committed_at": committed_at,
        "dirty": bool(status) if status_code == 0 else None,
    }


def _why_not(output: str) -> str:
    lowered = output.lower()
    if any(n in lowered for n in ("could not read username", "authentication failed", "terminal prompts disabled")):
        return "private repo — the agent has no GitHub credentials"
    if "not found" in lowered:
        return "repository not found on GitHub"
    return "couldn't reach GitHub"


def remote_tip(fetch_url: str, branch: str, cwd: str) -> tuple[str | None, str | None]:
    """What the remote's branch is at -> (sha, None), or (None, why not)."""
    try:
        done = subprocess.run(
            ["git", "-c", f"safe.directory={cwd}", "ls-remote", fetch_url, f"refs/heads/{branch}"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=REMOTE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "couldn't reach GitHub"

    if done.returncode != 0:
        return None, _why_not((done.stderr or "") + (done.stdout or ""))

    line = (done.stdout or "").strip().split("\n")[0]
    if not line:
        return None, f"no branch '{branch}' on GitHub"

    return line.split()[0], None


def compare(path: str, sha: str, remote_sha: str) -> str:
    if remote_sha == sha:
        return "up_to_date"

    # Is the remote's commit already in this checkout's history? Then the
    # checkout is ahead of it. Exit 1 (not an ancestor) and 128 (the commit
    # isn't here at all — it was pushed after the last fetch) both mean the
    # remote has something this checkout lacks.
    code, _ = _run(["merge-base", "--is-ancestor", remote_sha, "HEAD"], path)
    return "ahead" if code == 0 else "behind"


# ---------------------------------------------------------------------------
# What is tracked, and the last thing known about each
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_tracked: dict[str, dict] = {}   # checkout path -> {"fetch_url", "seen", "local_at", "remote_at"}
_state: dict[str, dict] = {}     # checkout path -> what lookup() returns
_remotes: dict[tuple[str, str], tuple[str | None, str | None, float]] = {}  # (url, branch) -> (sha, why, at)


def lookup(target: dict | None) -> dict | None:
    """The last known state of a project's checkout, for the container snapshot.

    ``target`` is rebuild.target_for(): None for a container that isn't built
    from a checkout, and nothing is said for a checkout whose remote isn't on
    GitHub.
    """
    if not target:
        return None

    repo = github_repo(target.get("remote")) or github_repo(target.get("fetch_url"))
    if not repo:
        return None

    path = target["path"]
    now = time.time()

    with _lock:
        entry = _tracked.setdefault(
            path, {"fetch_url": target.get("fetch_url"), "local_at": 0.0, "remote_at": 0.0}
        )
        entry["fetch_url"] = target.get("fetch_url")
        entry["seen"] = now
        known = _state.get(path)

    if known:
        return dict(known)

    owner, name = repo
    return {
        "owner": owner,
        "name": name,
        "url": f"https://github.com/{owner}/{name}",
        "state": "checking",
    }


def invalidate(path: str) -> None:
    """Look at this checkout again at the next tick — after a rebuild pulled it."""
    with _lock:
        entry = _tracked.get(path)
        if entry:
            entry["local_at"] = 0.0
            entry["remote_at"] = 0.0


def _refresh(path: str, entry: dict, now: float, *, remote: bool) -> None:
    info = local_info(path)
    repo = github_repo(entry.get("fetch_url"))
    if info is None or not repo:
        with _lock:
            _state.pop(path, None)
        return

    owner, name = repo
    state = {
        "owner": owner,
        "name": name,
        "url": f"https://github.com/{owner}/{name}",
        **info,
        "remote_sha": None,
        "remote_short": None,
        "state": "unknown",
        "error": None,
        "checked_at": None,
    }

    branch = info["branch"]
    if not branch:
        state["error"] = "not on a branch"
    else:
        key = (entry["fetch_url"], branch)
        with _lock:
            cached = _remotes.get(key)

        if remote or cached is None:
            sha, why = remote_tip(entry["fetch_url"], branch, path)
            cached = (sha, why, now)
            with _lock:
                _remotes[key] = cached

        sha, why, at = cached
        state["checked_at"] = at
        if sha:
            state["remote_sha"] = sha
            state["remote_short"] = sha[:7]
            state["state"] = compare(path, info["sha"], sha)
        else:
            state["error"] = why

    with _lock:
        _state[path] = state


def run_once(now: float | None = None) -> None:
    """One pass: forget what nobody asks about, refresh what has gone stale."""
    now = now or time.time()

    with _lock:
        for path in [p for p, e in _tracked.items() if now - e.get("seen", 0) > FORGET_AFTER]:
            _tracked.pop(path, None)
            _state.pop(path, None)
        due = [
            (path, dict(entry))
            for path, entry in _tracked.items()
            if now - entry["local_at"] >= local_seconds()
        ]

    for path, entry in due:
        remote = now - entry["remote_at"] >= remote_seconds()
        try:
            _refresh(path, entry, now, remote=remote)
        except Exception as error:  # noqa: BLE001 - one odd checkout must not stop the rest
            log.debug("repo refresh failed for %s: %s", path, error)
        with _lock:
            if path in _tracked:
                _tracked[path]["local_at"] = now
                if remote:
                    _tracked[path]["remote_at"] = now


def _worker() -> None:
    while True:
        try:
            run_once()
        except Exception as error:  # noqa: BLE001
            log.warning("repo status pass failed: %s", error)
        time.sleep(TICK)


def start() -> None:
    threading.Thread(target=_worker, daemon=True, name="repo-status").start()
