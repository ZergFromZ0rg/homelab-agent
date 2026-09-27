"""Interactive shells over a websocket: into a container, or onto the host.

This is the most powerful thing the agent does. A container shell is
``docker exec``; a host shell is root on the machine. So, like rebuilds,
it is **off unless ``TERMINAL_ENABLED`` is set**, and the route also wants
the agent token. The dashboard in front adds its own login and logs every
session to its activity feed.

**How a host shell works.** The agent lives in a container with the
host's filesystem mounted read-only and no view of its processes, so it
can't open a host shell itself. It starts a throwaway helper instead,
privileged and in the host's PID namespace, and execs ``nsenter -t 1 -a``
in that. The shell really is on the host — its mounts, network and
processes. It logs in as whoever owns the agent's own checkout (the
person who installed it), because a root shell leaves root-owned files
in their home directory, which is the rebuild helper's lesson all over
again. If that can't be worked out it is root.

**Why the shell prints its PID first.** ``docker exec`` has no "kill": a
browser tab closing drops the connection, and the process on the other
end carries on. So the command announces its PID in an OSC escape before
becoming the shell, the reader strips it, and on the way out the agent
sends that PID a SIGHUP — what a closing terminal does anyway. xterm
ignores unknown OSC sequences, so a marker that slipped through would be
invisible rather than garbage.

Wire protocol, both directions: binary frames are terminal bytes; text
frames are JSON control messages. In: ``{"type": "resize", "cols",
"rows"}``. Out: ``{"type": "exit", "code"}`` or ``{"type": "error",
"message"}``, then the socket closes.

  TERMINAL_ENABLED       "1" to allow shells. Off by default.
  TERMINAL_MAX_SESSIONS  concurrent shells on this host (default 8).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import threading
import uuid
from pathlib import Path

import config
import rebuild
from log import audit, log

MAX_SESSIONS = int(os.getenv("TERMINAL_MAX_SESSIONS", "8"))
HELPER_LABEL = "homelab-agent-terminal"

# \033]7788;<pid>\007 — see the module docstring.
PID_MARKER = re.compile(rb"\x1b\]7788;(\d+)\x07")
PID_SEARCH_LIMIT = 4096

_lock = threading.Lock()
_active = 0


def enabled() -> bool:
    return config.get("TERMINAL_ENABLED").strip().lower() in config.TRUTHY


ANNOUNCE = "printf '\\033]7788;%s\\007' $$; "

# bash when the image has it; plain sh (busybox, alpine) otherwise.
LOGIN_SHELL = (
    "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"
)


def container_command() -> list[str]:
    return ["sh", "-c", ANNOUNCE + LOGIN_SHELL]


def host_command(uid: int | None) -> list[str]:
    """The host shell, run inside the helper.

    The PID is announced from *inside* nsenter: entering a PID namespace
    only applies to children, so nsenter forks, and the process to hang up
    is the shell, not nsenter. The helper shares the host's PID namespace,
    so the number means the same thing from both sides.
    """
    login = (
        f'u=$(getent passwd {int(uid)} | cut -d: -f1); '
        'if [ -n "$u" ]; then exec su -l "$u"; fi; '
        if uid else ""
    )
    return [
        "nsenter", "-t", "1", "-a", "--",
        "sh", "-c", ANNOUNCE + login + "cd ~ 2>/dev/null; " + LOGIN_SHELL,
    ]


def owner_uid(checkout: str | None) -> int | None:
    """Who owns this agent's checkout (a path as seen from in here) — the
    login for a host shell. None when there is none or it's root's."""
    if not checkout:
        return None
    try:
        uid = Path(checkout).stat().st_uid
    except OSError:
        return None
    return uid or None


def cleanup_helpers(client) -> None:
    """Remove host-shell helpers a previous run of the agent left behind.
    They are ``sleep infinity`` in a privileged container — not something
    to leave lying around after a crash."""
    try:
        for container in client.containers.list(
            all=True, filters={"label": HELPER_LABEL}
        ):
            container.remove(force=True)
    except Exception as error:  # noqa: BLE001 - best effort
        log.debug("terminal helper cleanup failed: %s", error)


class Session:
    """One shell: the exec, its socket, and what to tear down after."""

    def __init__(self, client, container_id: str, cmd: list[str], helper=None):
        self.client = client
        self.container_id = container_id
        self.helper = helper
        self.pid: int | None = None
        self._scanned = b""
        self._size: tuple[int, int] | None = None
        self.exec_id = client.api.exec_create(
            container_id,
            cmd,
            stdin=True,
            tty=True,
            environment={"TERM": "xterm-256color", "COLORTERM": "truecolor"},
        )["Id"]
        raw = client.api.exec_start(self.exec_id, tty=True, socket=True)
        # docker-py hands back a SocketIO over the daemon connection; the
        # plain socket underneath is what supports recv/sendall.
        self.sock: socket.socket = getattr(raw, "_sock", raw)

    def resize(self, cols: int, rows: int) -> None:
        cols = max(1, min(int(cols), 1000))
        rows = max(1, min(int(rows), 1000))
        self._size = (cols, rows)
        try:
            self.client.api.exec_resize(self.exec_id, height=rows, width=cols)
        except Exception as error:  # noqa: BLE001 - races the exec starting
            log.debug("terminal resize failed: %s", error)

    def read(self) -> bytes:
        """The next output, or b"" once the shell has ended. A chunk that
        was nothing but the PID marker is not the end — read on."""
        while True:
            data = self.sock.recv(65536)
            if self.pid is not None or not data:
                return data
            data = self._strip_marker(data)
            if data:
                return data

    def _strip_marker(self, data: bytes) -> bytes:
        match = PID_MARKER.search(data)
        if match:
            self.pid = int(match.group(1))
            # A resize sent before the process was running can be lost;
            # the marker proves it is now, so apply the size again.
            if self._size:
                self.resize(*self._size)
            return data[: match.start()] + data[match.end():]
        self._scanned += data
        if len(self._scanned) > PID_SEARCH_LIMIT:
            self.pid = 0  # give up looking
        return data

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def exit_code(self) -> int | None:
        try:
            return self.client.api.exec_inspect(self.exec_id).get("ExitCode")
        except Exception:  # noqa: BLE001
            return None

    def close(self) -> None:
        try:
            running = self.client.api.exec_inspect(self.exec_id).get("Running")
        except Exception:  # noqa: BLE001
            running = False

        if running and self.pid:
            # Same container for a host shell: the helper shares the
            # host's PID namespace, so the PID means the same thing there.
            try:
                kill = self.client.api.exec_create(
                    self.container_id, ["sh", "-c", f"kill -HUP {int(self.pid)}"]
                )
                self.client.api.exec_start(kill["Id"])
            except Exception as error:  # noqa: BLE001
                log.debug("could not hang up shell %s: %s", self.pid, error)

        # shutdown, not just close: close alone doesn't wake a recv that
        # another thread is blocked in, and the reader would hang forever.
        for step in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                step()
            except OSError:
                pass

        if self.helper is not None:
            try:
                self.helper.remove(force=True)
            except Exception as error:  # noqa: BLE001
                log.debug("could not remove terminal helper: %s", error)


def open_container(client, container_id: str) -> Session:
    container = client.containers.get(container_id)
    if container.status != "running":
        raise ValueError(f"{container.name} isn't running")
    return Session(client, container.id, container_command())


def open_host(client, checkout: str | None) -> Session:
    helper = client.containers.run(
        rebuild.helper_image(client),
        command=["sleep", "infinity"],
        name=f"homelab-terminal-{uuid.uuid4().hex[:8]}",
        detach=True,
        auto_remove=True,
        privileged=True,
        pid_mode="host",
        network_mode="host",
        labels={HELPER_LABEL: "1"},
    )
    try:
        return Session(
            client, helper.id, host_command(owner_uid(checkout)),
            helper=helper,
        )
    except Exception:
        helper.remove(force=True)
        raise


async def serve(websocket, client, *, target: str, container_id: str | None,
                checkout: str | None, cols: int, rows: int, who: str) -> None:
    """Run one shell over an accepted websocket until either side ends."""
    global _active

    with _lock:
        if _active >= MAX_SESSIONS:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": f"this host already has {MAX_SESSIONS} shells open",
            }))
            await websocket.close()
            return
        _active += 1

    session = None
    label = "host" if target == "host" else f"container {container_id}"
    try:
        try:
            session = await asyncio.to_thread(
                open_host if target == "host" else open_container,
                client,
                checkout if target == "host" else container_id,
            )
        except Exception as error:  # noqa: BLE001 - shown to the user
            await websocket.send_text(json.dumps({
                "type": "error", "message": f"could not open a shell: {error}",
            }))
            await websocket.close()
            return

        audit.info("terminal: opened %s shell for %s", label, who)
        session.resize(cols, rows)
        await _pump(websocket, session)
    finally:
        with _lock:
            _active -= 1
        if session is not None:
            await asyncio.to_thread(session.close)
            audit.info("terminal: closed %s shell", label)


async def _pump(websocket, session: Session) -> None:
    async def from_shell():
        while True:
            try:
                data = await asyncio.to_thread(session.read)
            except OSError:
                data = b""
            if not data:
                return
            await websocket.send_bytes(data)

    async def to_shell():
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("bytes") is not None:
                await asyncio.to_thread(session.write, message["bytes"])
            elif message.get("text"):
                try:
                    control = json.loads(message["text"])
                except ValueError:
                    continue
                if control.get("type") == "resize":
                    await asyncio.to_thread(
                        session.resize, control.get("cols", 80), control.get("rows", 24)
                    )

    reader = asyncio.create_task(from_shell())
    writer = asyncio.create_task(to_shell())
    done, pending = await asyncio.wait(
        {reader, writer}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()

    if reader in done:
        # The shell ended on its own; say how, then hang up.
        code = await asyncio.to_thread(session.exit_code)
        try:
            await websocket.send_text(json.dumps({"type": "exit", "code": code}))
            await websocket.close()
        except Exception:  # noqa: BLE001 - the browser may be gone already
            pass
