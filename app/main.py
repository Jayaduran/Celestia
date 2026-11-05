import sys
from typing import Any
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.staticfiles import StaticFiles
import logging
import asyncio
from datetime import datetime, timedelta, timezone
from fastapi.responses import RedirectResponse

# Retention cleanup task definition
async def retention_cleanup_task():
    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
            storage_path = Path(settings.storage_dir)
            if storage_path.exists():
                for file_path in storage_path.rglob("*.*"):
                    try:
                        mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                        if mtime < cutoff:
                            file_path.unlink()
                            logging.info(f"Deleted old file: {file_path}")
                    except Exception as e:
                        logging.error(f"Error deleting file {file_path}: {e}")
        except Exception as e:
            logging.error(f"Retention cleanup error: {e}")
        await asyncio.sleep(24 * 60 * 60)  # Run once a day

# Silence Windows asyncio ProactorEventLoop WinError 10054 on sudden client socket disconnects
if sys.platform == "win32":
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport  # type: ignore
        _orig_call_connection_lost = getattr(_ProactorBasePipeTransport, "_call_connection_lost", None)

        def _silent_call_connection_lost(self: Any, exc: Any = None) -> None:
            try:
                if _orig_call_connection_lost:
                    _orig_call_connection_lost(self, exc)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                pass

        if hasattr(_ProactorBasePipeTransport, "_call_connection_lost"):
            setattr(_ProactorBasePipeTransport, "_call_connection_lost", _silent_call_connection_lost)
    except Exception:
        pass

from app.api.routes import (
    router as api_router,
    syslog_collector,
    file_collector,
    redpanda_collector,
    ingestion_queue,
    init_database_and_load_state,
)
from app.config import settings
from app.pipeline_monitor import global_throughput_monitor


import anyio
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    cores = os.cpu_count() or 4
    assigned_workers = int(os.getenv("WORKERS", "0"))
    if assigned_workers > 0:
        worker_count = assigned_workers
    else:
        worker_count = min(16, max(1, cores // 4))
    
    # Cap AnyIO threadpool to prevent threads jumping out of control
    anyio.to_thread.current_default_thread_limiter().total_tokens = worker_count


    # Startup: Connect persistent database and hydrate event state
    db_info = init_database_and_load_state()
    logging.info(f"[Database] Connected: {db_info.get('status')}, backend: {db_info.get('backend')}, total records: {db_info.get('total_in_db', 0)}")

    # Ensure MinIO bucket exists
    try:
        from app.storage.persistence import PersistenceManager
        PersistenceManager().minio.ensure_bucket()
    except Exception:
        pass

    # Start background queue, log collectors, and real-time throughput monitor
    ingestion_queue.start()
    await syslog_collector.start_async()
    file_collector.start()
    global_throughput_monitor.start_console_monitor()
    if settings.redpanda_enabled:
        redpanda_collector.start()
    # Start retention cleanup background task
    app.state.retention_task = asyncio.create_task(retention_cleanup_task())
    yield
    # Shutdown: Gracefully stop background collectors, queue, and monitor
    global_throughput_monitor.stop_console_monitor()
    if settings.redpanda_enabled:
        redpanda_collector.stop()
    syslog_collector.stop()
    file_collector.stop()
    ingestion_queue.stop()
    # Cancel retention cleanup task
    retention_task = getattr(app.state, "retention_task", None)
    if retention_task:
        retention_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass



app = FastAPI(
    title=settings.app_name,
    description="Universal Log Pre-processing Framework (ULPF) — SIH Problem SIH 26156 Master Implementation",
    version=settings.version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit logging & Cache prevention middleware
@app.middleware("http")
async def audit_log(request: Request, call_next):
    # Skip noisy polling routes to keep Docker logs clean
    noisy_routes = ("/api/v1/health", "/api/v1/metrics", "/api/v1/sources", "/api/v1/events")
    is_noisy = any(request.url.path.startswith(r) for r in noisy_routes)

    if not is_noisy:
        logger = logging.getLogger("audit")
        client_host = request.client.host if request.client else "unknown"
        logger.info(f"{datetime.now(timezone.utc).isoformat()} - {client_host} - {request.method} {request.url.path}")
        
    response = await call_next(request)
    if request.url.path.startswith("/dashboard"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.include_router(api_router)


@app.get("/")
def read_root():
    return RedirectResponse(url="/dashboard/")




# Mount Web Dashboard static directory if present
dashboard_dir = Path(__file__).parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")

# Mount Testing Website Hub static directory if present
testing_dir = Path(__file__).parent.parent.parent / "testing" / "web"
if not testing_dir.exists():
    testing_dir = Path(__file__).parent.parent / "testing" / "web"
if testing_dir.exists():
    app.mount("/testing", StaticFiles(directory=str(testing_dir), html=True), name="testing_web")
