#!/usr/bin/env python3
"""
ULPF Main Worker Runner.
Boots the core pipeline, ingestion collectors (Syslog UDP:5140, TCP:5141),
SQLite metadata persistence, and FastAPI REST/Dashboard service on port 8000.
"""

import sys
import os
from pathlib import Path

# Ensure working directory is main/
MAIN_DIR = Path(__file__).resolve().parent
os.chdir(MAIN_DIR)
if str(MAIN_DIR) not in sys.path:
    sys.path.insert(0, str(MAIN_DIR))

# Ensure storage directories exist
(MAIN_DIR / "storage" / "raw").mkdir(parents=True, exist_ok=True)
(MAIN_DIR / "storage" / "logs").mkdir(parents=True, exist_ok=True)

# Point storage paths to main/storage
os.environ.setdefault("STORAGE_DIR", str(MAIN_DIR / "storage" / "raw"))
os.environ.setdefault("DB_SQLITE_PATH", str(MAIN_DIR / "storage" / "ulpf_metadata.db"))
if __name__ == "__main__":
    import uvicorn
    from app.config import settings

    host = os.getenv("ULPF_API_HOST", "0.0.0.0")
    port = int(os.getenv("ULPF_API_PORT", "8000"))

    print("=" * 70)
    print("  [ULPF CORE 1: MAIN WORKER]")
    print(f"  API & Dashboard: http://{host}:{port}/ (Local: http://127.0.0.1:{port}/)")
    print(f"  Syslog UDP Ingress Port: {settings.syslog_udp_port}")
    print(f"  Syslog TCP Ingress Port: {settings.syslog_tcp_port}")
    print(f"  Database Storage: {settings.db_sqlite_path}")
    print(f"  AI Sovereign Engine: {settings.ai_provider.upper()} ({settings.ai_model_name}) @ {settings.ollama_host}")
    print("=" * 70)

    uvicorn.run("app.main:app", host=host, port=port, log_level="info", access_log=False)
