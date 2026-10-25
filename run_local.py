"""Convenience entrypoint: run a local encrypted relay and open the desktop GUI."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from desktop_gui import NoxCipherGUI


RELAY_HEALTH = "http://127.0.0.1:8765/health"


def relay_running() -> bool:
    try:
        with urllib.request.urlopen(RELAY_HEALTH, timeout=0.5) as response:
            data = json.load(response)
            if data.get("service") != "noxcipher-relay":
                raise RuntimeError("Port 8765 is used by a different service. Stop it before launching NoxCipher.")
            return True
    except urllib.error.HTTPError as exc:
        raise RuntimeError("Port 8765 is occupied by another HTTP service.") from exc
    except (ConnectionError, TimeoutError, OSError):
        return False


def main() -> None:
    server = None
    try:
        if not relay_running():
            server = subprocess.Popen([sys.executable, "-m", "uvicorn", "relay_server:app",
                                       "--host", "127.0.0.1", "--port", "8765", "--no-access-log"],
                                      cwd=Path(__file__).parent,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(40):
                if server.poll() is not None:
                    raise RuntimeError("Local relay did not start; run the relay manually to inspect errors.")
                time.sleep(0.1)
                if relay_running():
                    break
            else:
                raise RuntimeError("Local relay did not respond at port 8765.")
        NoxCipherGUI().run()
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=4)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"NoxCipher launcher error: {exc}", file=sys.stderr)
        sys.exit(1)
