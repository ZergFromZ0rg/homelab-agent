"""Self-registration with a homelab-dashboard instance.

If ``DASHBOARD_URL`` is set, the agent POSTs its name and reachable URL to
``{DASHBOARD_URL}/api/nodes`` on startup and every ``REGISTER_INTERVAL``
seconds afterward, so the dashboard picks it up (and keeps it marked live)
without any manual node configuration.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


class Registrar:
    def __init__(self, host_name: str):
        self.host_name = host_name
        self.dashboard_url = os.getenv("DASHBOARD_URL", "").strip().rstrip("/")
        self.agent_url = (
            os.getenv("AGENT_URL", "").strip().rstrip("/")
            or f"http://{host_name}:8123"
        )
        self.token = os.getenv("REGISTER_TOKEN", "").strip()
        self.interval = _env_int("REGISTER_INTERVAL", 60, 15)

    @property
    def enabled(self) -> bool:
        return bool(self.dashboard_url)

    def start(self) -> None:
        if not self.enabled:
            print(
                "dashboard self-registration disabled "
                "(set DASHBOARD_URL to enable)"
            )
            return

        if not self.host_name or self.host_name == "unknown":
            print(
                "dashboard self-registration skipped: "
                "set HOST_NAME to match the machine's Prometheus job"
            )
            return

        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()

    def _register_once(self) -> None:
        endpoint = f"{self.dashboard_url}/api/nodes"
        payload = json.dumps({
            "name": self.host_name,
            "url": self.agent_url,
        }).encode()

        request = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )

        if self.token:
            request.add_header("X-Register-Token", self.token)

        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()

    def _loop(self) -> None:
        while True:
            try:
                self._register_once()
            except (urllib.error.URLError, OSError, ValueError) as error:
                print(f"dashboard registration failed: {error}")

            time.sleep(self.interval)
