"""Logging config for the agent. Logs to stdout so ``docker logs`` picks it
up. ``LOG_LEVEL`` sets verbosity (default INFO).

``audit`` carries every container/stack mutation and every policy
rejection — filter to it for a record of what was asked of this host:

    docker logs homelab-agent 2>&1 | grep ' audit '
"""

from __future__ import annotations

import logging
import os
import sys

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-6s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
)
_level = os.getenv("LOG_LEVEL", "INFO").upper()

for _name in ("agent", "audit"):
    _lg = logging.getLogger(_name)
    _lg.setLevel(_level)
    _lg.handlers[:] = [_handler]
    _lg.propagate = False

log = logging.getLogger("agent")
audit = logging.getLogger("audit")
