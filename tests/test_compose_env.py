"""Every setting the agent reads must actually reach the container.

A compose *variable* and a container *environment variable* are not the
same thing, and the difference is invisible: ``${BACKUP_HOST_DIR}`` in a
volume line works perfectly for the mount while the agent, reading
``os.getenv("BACKUP_HOST_DIR")``, sees nothing at all.

That shipped. The one-variable backup setup quietly did not work — it only
looked like it did because the host still had an older, superseded setting
that happened to cover for it. This test is why it cannot happen again.
"""

import pathlib
import re

import config

ROOT = pathlib.Path(__file__).resolve().parent.parent


def environment_keys() -> set[str]:
    text = (ROOT / "compose.yml").read_text()
    block = text.split("environment:", 1)[1].split("\n    volumes:", 1)[0]
    return set(re.findall(r"^\s{6}([A-Z_][A-Z0-9_]*):", block, re.M))


def test_every_setting_reaches_the_container():
    missing = sorted(s["key"] for s in config.SETTINGS if s["key"] not in environment_keys())

    assert not missing, (
        "these are read by the agent but never passed into the container, so "
        f"they always read as unset: {missing}"
    )


def test_the_environment_block_was_actually_found():
    """A parser that silently matches nothing would make the test above
    pass forever."""
    keys = environment_keys()

    assert "HOST_NAME" in keys
    assert len(keys) > 10
