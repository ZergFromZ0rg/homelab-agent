"""The capture and network-watch controllers keep state in module globals; the
suite resets it after every test (see conftest.py). Parametrized rounds run in
order, so rounds 2 and 3 only pass if round 1's leftovers were really cleared."""

import pytest

import capture
import netwatch


@pytest.mark.parametrize("round_", [1, 2, 3])
def test_state_left_by_one_test_does_not_reach_the_next(round_, tmp_path):
    assert capture._job is None and capture._container is None and capture._starting is False
    assert capture._interfaces_cache is None
    assert netwatch._detector is None and netwatch._enabled is False and netwatch._status["state"] == "off"
    assert netwatch.STATE_FILE.parent == tmp_path  # never the real /data

    # ...and now make a mess.
    capture._job = capture._fresh({"iface": "eth0", "filter": {}, "payload": "none", "promisc": False, "duration": 5})
    capture._starting = True
    capture._interfaces_cache = (0.0, {"default": "eth0"})
    netwatch._detector = netwatch.Detector(None, now=1.0)
    netwatch._status["state"] = "watching"
