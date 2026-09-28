"""A container's logs: streamed live over a websocket, or downloaded whole.

Reading, not changing, so it needs only the agent token — no opt-in like
the terminal. The stream sends the last ``tail`` lines, then follows until
the container stops or the viewer leaves; stopped containers just send
their tail and end (which is usually when you want the logs most).

docker-py's streaming ``logs()`` blocks, so it runs in a thread feeding a
queue. When the viewer leaves, the stream is closed, which ends the thread
— otherwise every closed tab would leave a follower running forever.
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time

from log import log

MAX_TAIL = 5000


def _clamp_tail(value) -> int:
    try:
        return max(1, min(int(value), MAX_TAIL))
    except (TypeError, ValueError):
        return 500


def _since(value) -> int | None:
    """Seconds back from now, as the Unix time Docker wants; None = no limit."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    return int(time.time()) - seconds if seconds > 0 else None


async def stream(websocket, client, container_id: str, *, tail, timestamps: bool, since=None) -> None:
    try:
        container = client.containers.get(container_id)
    except Exception as error:  # noqa: BLE001 - shown to the user
        await websocket.send_text(json.dumps({"type": "error", "message": f"no such container: {error}"}))
        await websocket.close()
        return

    follow = container.status == "running"
    try:
        start = _since(since)
        logs = client.api.logs(
            container.id, stream=True, follow=follow, timestamps=timestamps,
            # A time range reads everything in it (up to MAX_TAIL lines);
            # otherwise the last `tail` lines.
            tail=MAX_TAIL if start else _clamp_tail(tail),
            **({"since": start} if start else {}),
        )
    except Exception as error:  # noqa: BLE001
        await websocket.send_text(json.dumps({"type": "error", "message": f"can't read logs: {error}"}))
        await websocket.close()
        return

    chunks: queue.Queue = queue.Queue(maxsize=256)

    def pump():
        try:
            for chunk in logs:
                chunks.put(chunk)
        except Exception as error:  # noqa: BLE001 - closed under us, usually
            log.debug("log stream ended: %s", error)
        finally:
            chunks.put(None)

    threading.Thread(target=pump, daemon=True).start()

    async def to_viewer():
        while True:
            chunk = await asyncio.to_thread(chunks.get)
            if chunk is None:
                return
            await websocket.send_bytes(chunk)

    async def viewer_left():
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return

    sender = asyncio.create_task(to_viewer())
    watcher = asyncio.create_task(viewer_left())
    done, pending = await asyncio.wait({sender, watcher}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    try:
        logs.close()
    except Exception:  # noqa: BLE001
        pass
    if sender in done:
        try:
            await websocket.send_text(json.dumps({
                "type": "exit", "code": None,
                "reason": "the container stopped" if follow else "end of the log",
            }))
            await websocket.close()
        except Exception:  # noqa: BLE001 - the viewer may be gone
            pass


def download(client, container_id: str):
    """All of a container's logs, with timestamps, as a byte generator."""
    container = client.containers.get(container_id)
    return client.api.logs(container.id, stream=True, follow=False, timestamps=True), container.name
