#!/usr/bin/env python3
"""
ULPF Testing Simulator Website Runner.
Boots the dedicated Testing & Network Protocol Simulator Web Application on port 8050.
"""

import sys
import os
from pathlib import Path

# Add root, testing/, testing/server, and main/ to sys.path
TESTING_DIR = Path(__file__).resolve().parent
SERVER_DIR = TESTING_DIR / "server"
ROOT_DIR = TESTING_DIR.parent

for p in [ROOT_DIR, TESTING_DIR, SERVER_DIR, ROOT_DIR / "main"]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

os.chdir(ROOT_DIR)

# Silence Windows asyncio ProactorEventLoop WinError 10054 on sudden client socket disconnects
if sys.platform == "win32":
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        _orig_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost

        def _silent_call_connection_lost(self, exc=None):
            try:
                _orig_call_connection_lost(self, exc)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                pass

        _ProactorBasePipeTransport._call_connection_lost = _silent_call_connection_lost
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("TESTING_HOST", "0.0.0.0")
    port = int(os.getenv("PORT") or os.getenv("TESTING_PORT") or 8050)

    print("=" * 70)
    print("  [ULPF CORE 2: PROTOCOL SIMULATOR & TESTING HUB]")
    print(f"  Testing Website: http://{host}:{port}/ (Local: http://127.0.0.1:{port}/)")
    print(f"  Target Main Worker: 127.0.0.1 (API:8000, UDP:5140, TCP:5141)")
    print("=" * 70)

    uvicorn.run("sim_server:app", host=host, port=port, app_dir=str(SERVER_DIR), log_level="info")
