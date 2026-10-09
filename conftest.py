# Keeps pytest's rootdir at the repo root so `import deploy` / `import main`
# resolve the same way they do under `uvicorn main:app`.

import sys

import pytest


@pytest.fixture(autouse=True)
def _no_capture_state_leaks(tmp_path, monkeypatch):
    """The capture and network-watch controllers keep their state in module
    globals (the current job, the detector, a supervisor thread). Reset them after
    every test so none can leak into the next, and keep the watch's state file off
    /data. Only modules already imported are touched."""
    watch = sys.modules.get("netwatch")
    if watch:
        monkeypatch.setattr(watch, "STATE_FILE", tmp_path / "netwatch.json")
    yield
    capture = sys.modules.get("capture")
    if capture:
        capture._job = capture._container = capture._interfaces_cache = None
        capture._starting = False
    if watch:
        if watch._enabled:
            watch.disable()
        watch._detector = None
        watch._status.update(state="off", iface=None, since=None, error=None, beat=None)
