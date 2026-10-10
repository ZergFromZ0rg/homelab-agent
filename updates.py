"""Image updates: is there a newer image for this container, and update it.

**Checking** asks each image's registry for the manifest its tag points to
now, and compares the one *for this host's platform* with the one the
container runs. Comparing the top-level digest instead would flag images
whose bits for this machine haven't changed: Docker Hub re-publishes
official images under the same tag (new attestations, other platforms
rebuilt), which moves the index digest and nothing else. The local
per-platform digest comes from the containerd image store
(``/images/{id}/json?manifests=1``); a daemon on the classic store has no
per-platform record, so there the tag's own digest is compared and says so.

The registry is asked directly and anonymously (the standard bearer-token
challenge), which covers Docker Hub, ghcr.io, lscr.io and quay.io without
setup. An image that isn't in any registry — built on this host — answers
401/404 and is ``local``: nothing to compare against, and no badge. Checks
run every ``UPDATE_CHECK_HOURS`` (6) and on request; results are cached per
image, so a tag used by five containers is one request.

**Updating** is Compose's: ``pull`` then ``up -d`` for the services, in the
same helper as a compose change, then the same watch (compose_edit.watch).
The image being replaced is tagged ``<repo>:hl-rollback`` first; if a
container doesn't come up, that tag is moved back onto the original one
and ``up -d`` runs again. Only Compose-started containers, and only where
``REBUILD_ENABLED`` is on — the same switch as compose changes.

``AUTO_UPDATE_AT`` ("03:30", the host's own time zone, read from its
/etc/localtime) runs a check and then updates everything with an update,
once a day. Off unless set.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import requests

import compose_edit
import config
import disk_usage
import rebuild
from log import audit, log

CHECK_HOURS = float(config.get("UPDATE_CHECK_HOURS") or 6)
TIMEOUT = 15
ROLLBACK_TAG = "hl-rollback"

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

_cache: dict[str, dict] = {}
_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_wake = threading.Event()


# --- registries ---------------------------------------------------------------


def split_ref(ref: str) -> tuple[str, str, str]:
    """``(registry, repository, tag)`` the way Docker resolves a name."""
    name = ref.split("@")[0]
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = name.rsplit(":", 1)
    else:
        tag = "latest"
    first = name.split("/")[0]
    if first in ("docker.io", "index.docker.io") and "/" in name:
        name = name[len(first) + 1:]
    elif "/" in name and ("." in first or ":" in first or first == "localhost"):
        return first, name[len(first) + 1:], tag
    return "registry-1.docker.io", name if "/" in name else f"library/{name}", tag


class NotInRegistry(Exception):
    """The registry doesn't have it (or won't say) — a local build."""


def _manifest(session, registry: str, repo: str, reference: str):
    # Docker itself talks plain http to a registry on localhost.
    scheme = "http" if registry.split(":")[0] in ("localhost", "127.0.0.1") else "https"
    url = f"{scheme}://{registry}/v2/{repo}/manifests/{reference}"
    response = session.get(url, headers={"Accept": ACCEPT}, timeout=TIMEOUT)
    challenge = response.headers.get("WWW-Authenticate", "")
    if response.status_code == 401 and challenge.lower().startswith("bearer"):
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.pop("realm", None)
        if realm:
            params.setdefault("scope", f"repository:{repo}:pull")
            token = session.get(realm, params=params, timeout=TIMEOUT).json()
            session.headers["Authorization"] = "Bearer " + (
                token.get("token") or token.get("access_token") or ""
            )
            response = session.get(url, headers={"Accept": ACCEPT}, timeout=TIMEOUT)
    if response.status_code in (401, 403, 404):
        raise NotInRegistry(f"{registry} has no {repo}:{reference} it will show us")
    response.raise_for_status()
    return response


def _matches(entry: dict, platform: dict) -> bool:
    p = entry.get("platform") or {}
    if p.get("os") != platform.get("os") or p.get("architecture") != platform.get("architecture"):
        return False
    return not platform.get("variant") or p.get("variant") in (None, platform["variant"])


def remote_digests(ref: str, platform: dict | None) -> dict:
    """``{"index": digest of the tag, "platform": digest for this platform}``."""
    registry, repo, tag = split_ref(ref)
    session = requests.Session()
    response = _manifest(session, registry, repo, tag)
    index = response.headers.get("Docker-Content-Digest")
    body = response.json()
    if "manifests" not in body:
        return {"index": index, "platform": index}
    if not platform:
        return {"index": index, "platform": None}
    for entry in body["manifests"]:
        if _matches(entry, platform):
            return {"index": index, "platform": entry.get("digest")}
    return {"index": index, "platform": None}


# --- what's here ----------------------------------------------------------------


def local_digests(client, image_id: str) -> dict:
    """The digests this host has for an image: the per-platform manifest
    it runs (containerd store), and the tag's index digest(s)."""
    data = client.api._result(
        client.api._get(client.api._url("/images/{0}/json", image_id), params={"manifests": "1"}),
        True,
    )
    running = [
        m for m in data.get("Manifests") or []
        if m.get("Kind") == "image" and m.get("Available")
    ]
    return {
        "platform": running[0]["Descriptor"]["digest"] if running else None,
        "platform_info": (running[0]["Descriptor"].get("platform") if running else None),
        "index": [d.split("@", 1)[1] for d in data.get("RepoDigests") or [] if "@" in d],
    }


def check_ref(client, ref: str, image_id: str) -> dict:
    now = time.time()
    if "@sha256:" in ref:
        return {"state": "pinned", "checked_at": now}
    try:
        local = local_digests(client, image_id)
        remote = remote_digests(ref, local["platform_info"])
    except NotInRegistry:
        return {"state": "local", "checked_at": now}
    except Exception as error:  # noqa: BLE001 - network, odd registry
        return {"state": "unknown", "checked_at": now, "error": str(error)[:200]}

    if local["platform"] and remote["platform"]:
        newer = local["platform"] != remote["platform"]
        basis = "platform"
    else:
        newer = remote["index"] not in local["index"]
        basis = "tag"
    return {
        "state": "available" if newer else "current",
        "checked_at": now,
        "basis": basis,
        "remote": remote["platform"] or remote["index"],
    }


def check_all(client) -> dict:
    """Check every image a container uses; one request set per image."""
    refs: dict[str, str] = {}
    for container in client.containers.list(all=True):
        ref = container.attrs.get("Config", {}).get("Image")
        if ref:
            refs.setdefault(ref, container.attrs.get("Image"))
    for ref, image_id in refs.items():
        result = check_ref(client, ref, image_id)
        with _lock:
            _cache[ref] = {**result, "image_id": image_id}
    audit.info("updates: checked %d images, %d with updates", len(refs),
               sum(1 for r in refs if _cache.get(r, {}).get("state") == "available"))
    return snapshot()


def snapshot() -> dict:
    with _lock:
        return {ref: dict(v) for ref, v in _cache.items()}


def for_container(container, labels: dict | None) -> dict | None:
    """The ``update`` block ``GET /containers`` carries per container."""
    ref = container.attrs.get("Config", {}).get("Image")
    with _lock:
        cached = dict(_cache.get(ref) or {})
    if not cached:
        return None
    # The image was changed since the check (pulled, rebuilt): stale.
    if cached.get("image_id") and cached["image_id"] != container.attrs.get("Image"):
        cached["state"] = "unchecked"
    labels = labels or {}
    why_not = None
    if cached.get("state") == "available":
        if not labels.get("com.docker.compose.project"):
            why_not = "not started by Compose — recreate it yourself"
        elif not rebuild.enabled():
            why_not = "this host doesn't allow rebuilds and compose changes"
    return {
        "state": cached.get("state"),
        "checked_at": cached.get("checked_at"),
        "basis": cached.get("basis"),
        "can_update": cached.get("state") == "available" and why_not is None,
        "why_not": why_not,
    }


# --- updating -------------------------------------------------------------------


def _public(job: dict) -> dict:
    return {**{k: v for k, v in job.items() if not k.startswith("_")},
            "steps": list(job["steps"]), "progress": dict(job.get("progress") or {})}


def status(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return _public(job) if job else None


def recent() -> list[dict]:
    with _lock:
        return [_public(j) for j in
                sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)[:10]]


def _step(job, text, output=None):
    with _lock:
        job["steps"].append({"at": time.time(), "text": text, "output": output})


class PullProgress:
    """Bytes downloaded across every layer of every image being pulled.

    Docker streams one event per layer; a layer's size is only known once
    its download starts, so the total grows as the pull goes. The figure
    only ever moves forward (a late-announced layer must not drag the bar
    back) and reads 100% when the stream ends.
    """

    def __init__(self):
        self.layers: dict[tuple, dict] = {}
        self.extracting = False
        self.peak = 0.0

    def feed(self, ref: str, event: dict) -> None:
        layer, status = event.get("id"), event.get("status") or ""
        if not layer or status.startswith(("Pulling from", "Digest", "Status")):
            return
        entry = self.layers.setdefault((ref, layer), {"current": 0, "total": 0})
        detail = event.get("progressDetail") or {}
        if status == "Downloading" and detail.get("total"):
            entry["current"], entry["total"] = detail.get("current", 0), detail["total"]
        elif status in ("Download complete", "Pull complete", "Already exists"):
            entry["current"] = entry["total"]
        elif status == "Extracting":
            entry["current"] = entry["total"]
            self.extracting = True

    def bytes(self) -> tuple[int, int]:
        return (sum(e["current"] for e in self.layers.values()),
                sum(e["total"] for e in self.layers.values()))

    def fraction(self) -> float:
        done, total = self.bytes()
        self.peak = max(self.peak, min(1.0, done / total) if total else 0.0)
        return self.peak


# How much of a project's share of the bar each stage takes: the pull is
# the long part, then recreating the containers, then watching them start.
PULL_SHARE, UP_SHARE = 0.85, 0.10


def _progress(job, index: int, total: int, within: float, phase: str, **extra) -> None:
    with _lock:
        job["progress"] = {
            "percent": round(100 * (index + min(1.0, within)) / max(total, 1), 1),
            "phase": phase, **extra,
        }


def plan(client, names: list[str] | None) -> dict[str, dict]:
    """``{project: {info, services: {service: ref}}}`` for what to update.
    ``names`` None means everything with an update available."""
    projects: dict[str, dict] = {}
    for container in client.containers.list(all=True):
        if names is not None and container.name not in names and container.id not in names:
            continue
        labels = container.labels or {}
        block = for_container(container, labels)
        if not block or not block["can_update"]:
            if names is not None:
                raise disk_usage.DiskUsageError(
                    f"{container.name}: " + ((block or {}).get("why_not") or "no update known — check first")
                )
            continue
        info = compose_edit.target(client, container.id)
        if info["project"] == rebuild.self_project(client):
            if names is not None:
                raise disk_usage.DiskUsageError("the agent updates itself with a rebuild")
            continue
        entry = projects.setdefault(info["project"], {"info": info, "services": {}})
        entry["services"][info["service"]] = container.attrs["Config"]["Image"]
    return projects


def start(client, names: list[str] | None, *, by: str = "dashboard") -> dict:
    projects = plan(client, names)
    if not projects:
        raise disk_usage.DiskUsageError("nothing here has an update to apply")
    with _lock:
        if any(j["state"] == "running" for j in _jobs.values()):
            raise compose_edit.files.Conflict("an update is already running on this host")
        job = {
            "id": uuid.uuid4().hex[:12], "state": "running", "by": by,
            "projects": sorted(projects), "steps": [], "results": {},
            "started_at": time.time(), "finished_at": None,
            "progress": {"percent": 0.0, "phase": "starting"}, "_index": 0,
        }
        _jobs[job["id"]] = job
    threading.Thread(target=_run, args=(client, job, projects), daemon=True).start()
    return status(job["id"])


def local_name(ref: str) -> tuple[str, str]:
    """``(repository, tag)`` as the image is named on this host — what a
    retag has to reproduce for Compose to find it again."""
    name = ref.split("@")[0]
    if ":" in name.rsplit("/", 1)[-1]:
        repo, tag = name.rsplit(":", 1)
        return repo, tag
    return name, "latest"


def _update_project(client, job, project: str, entry: dict) -> str:
    info, services = entry["info"], entry["services"]
    names = sorted(services)
    old = {}
    for service, ref in services.items():
        image = client.images.get(ref)
        old[service] = image.id
        # A name for the image being replaced, so a prune during the job
        # can't take it (the pull moves the real tag off it). One per
        # service: two services on one repository would share a tag.
        image.tag(local_name(ref)[0], _rollback_tag(service))
    try:
        return _pull_and_watch(client, job, project, info, services, names, old)
    finally:
        for service, ref in services.items():
            try:
                client.images.remove(f"{local_name(ref)[0]}:{_rollback_tag(service)}", noprune=True)
            except Exception as error:  # noqa: BLE001 - leaving a tag behind is harmless
                log.debug("could not drop rollback tag: %s", error)


def _pull_images(client, job, project, services, index: int, total: int) -> str | None:
    """Pull each service's image through the Docker API, publishing byte
    progress on the job. The pull's last status lines, or None when it
    couldn't be streamed (the caller falls back to Compose)."""
    progress, lines = PullProgress(), []
    try:
        for ref in sorted(set(services.values())):
            repository, tag = local_name(ref)
            _progress(job, index, total, progress.fraction() * PULL_SHARE, f"pulling {repository}:{tag}")
            last = 0.0
            for event in client.api.pull(repository, tag=tag, stream=True, decode=True):
                if event.get("error"):
                    raise RuntimeError(event["error"])
                progress.feed(ref, event)
                if event.get("status") and not event.get("progressDetail"):
                    lines.append(event["status"])
                now = time.monotonic()
                if now - last >= 0.5:
                    last = now
                    done, size = progress.bytes()
                    _progress(
                        job, index, total, progress.fraction() * PULL_SHARE,
                        ("extracting " if progress.extracting and done >= size else "pulling ") + f"{repository}:{tag}",
                        bytes_done=done, bytes_total=size,
                    )
    except Exception as error:  # noqa: BLE001 - any failure here falls back to Compose
        log.warning("streamed pull of %s failed (%s); falling back to compose pull", project, error)
        return None
    done, size = progress.bytes()
    _progress(job, index, total, PULL_SHARE, f"pulled {project}", bytes_done=done, bytes_total=size)
    return "\n".join(lines)


def _rollback_tag(service: str) -> str:
    return f"{ROLLBACK_TAG}-{re.sub(r'[^A-Za-z0-9_.-]', '-', service)}"[:128]


def _pull_and_watch(client, job, project, info, services, names, old) -> str:

    index, total = job["_index"], len(job["projects"])
    pulled = _pull_images(client, job, project, services, index, total)
    if pulled is not None:
        _step(job, f"{project}: pulled {', '.join(names)}", pulled[-2000:])
    else:
        # Streaming the pull ourselves didn't work (a registry the agent
        # can't reach but Compose's own config can): Compose's pull, with
        # no byte counts.
        _progress(job, index, total, 0, f"pulling {', '.join(names)}")
        code, output = compose_edit._run_helper(
            client,
            compose_edit._compose_args(info, "", "") + ["pull", *names],
            compose_edit._mounts(info, socket=True), network=True,
        )
        _step(job, f"{project}: pulled {', '.join(names)}", output[-2000:])
        if code != 0:
            return f"pull failed (exit {code})"

    _progress(job, index, total, PULL_SHARE, f"recreating {project}")
    code, output = compose_edit._up(client, info)
    _progress(job, index, total, PULL_SHARE + UP_SHARE, f"waiting for {project} to come up")
    _step(job, f"{project}: docker compose up -d", output[-2000:])
    failed = (
        {"name": project, "why": f"up failed (exit {code})"} if code != 0
        else compose_edit.watch(client, project)
    )
    if failed is None:
        for service, ref in services.items():
            with _lock:
                _cache.pop(ref, None)
        return "done"

    logs = compose_edit._logs(client, failed["name"])
    _step(job, f"{project}: {failed['name']} {failed['why']} — rolling back", logs)
    for service, ref in services.items():
        client.images.get(old[service]).tag(*local_name(ref))
    code, output = compose_edit._up(client, info)
    _step(job, f"{project}: back on the previous image", output[-2000:])
    return f"rolled back: {failed['name']} {failed['why']}"


def _run(client, job, projects) -> None:
    try:
        for index, (project, entry) in enumerate(sorted(projects.items())):
            job["_index"] = index
            try:
                result = _update_project(client, job, project, entry)
            except Exception as error:  # noqa: BLE001 - one project's failure isn't the others'
                log.exception("update of %s failed", project)
                result = f"failed: {error}"
            with _lock:
                job["results"][project] = result
            audit.info("updates: %s %s", project, result)
        outcomes = set(job["results"].values())
        state = "done" if outcomes == {"done"} else (
            "rolled_back" if any(r.startswith("rolled back") for r in outcomes) else "failed"
        )
    except Exception as error:  # noqa: BLE001
        log.exception("update job failed")
        state = "failed"
        job["results"]["_"] = str(error)
    with _lock:
        job["state"] = state
        job["finished_at"] = time.time()
        job["progress"] = {"percent": 100.0, "phase": state}
    _wake.set()  # re-check soon, so badges clear


# --- the background loop ---------------------------------------------------------


def host_zone():
    try:
        with open(disk_usage._on_host("/etc/localtime"), "rb") as f:
            return ZoneInfo.from_file(f)
    except Exception:  # noqa: BLE001 - UTC is a fine fallback
        return ZoneInfo("UTC")


def _due(at: str, now: datetime, last_day: str | None) -> bool:
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", at.strip())
    if not match:
        return False
    hour, minute = int(match.group(1)), int(match.group(2))
    today = now.strftime("%Y-%m-%d")
    return last_day != today and (now.hour, now.minute) >= (hour, minute) and now.hour == hour


def loop(client) -> None:
    last_check = 0.0
    last_auto_day = None
    zone = host_zone()
    while True:
        try:
            if time.time() - last_check >= CHECK_HOURS * 3600 or _wake.is_set():
                _wake.clear()
                check_all(client)
                last_check = time.time()
            at = config.get("AUTO_UPDATE_AT").strip()
            now = datetime.now(zone)
            if at and rebuild.enabled() and _due(at, now, last_auto_day):
                last_auto_day = now.strftime("%Y-%m-%d")
                check_all(client)
                try:
                    start(client, None, by="nightly")
                except Exception as error:  # noqa: BLE001 - nothing to update is normal
                    log.info("nightly update: %s", error)
        except Exception as error:  # noqa: BLE001
            log.warning("update check failed: %s", error)
        _wake.wait(timeout=60)


def start_loop(client) -> None:
    threading.Thread(target=loop, args=(client,), daemon=True).start()


def check_soon() -> None:
    _wake.set()
