import os
import time
import threading
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone
from app.collectors.base import BaseConnector
from app.collectors.ingress import RawIngress
from app.collectors.queue import IngestionQueue
from app.config import settings

logger = logging.getLogger(__name__)


class FileCollector(BaseConnector):
    """
    Persistent File Tail Collector & Log File Ingestion Engine.
    Monitors log files (e.g. storage/logs/*.log), tails newly appended lines,
    tracks file byte offsets, detects log rotation, and ingests batch files.
    """

    def __init__(
        self,
        watch_dir: Optional[str] = None,
        queue: Optional[IngestionQueue] = None,
        pipeline: Optional[Any] = None,
        event_callback: Optional[Callable] = None,
    ):
        super().__init__(name="File Tail Collector", connector_type="file_tail")
        self.watch_dir = Path(watch_dir or settings.file_watch_dir)
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.queue = queue
        self.pipeline = pipeline
        self.event_callback = event_callback
        self.watched_files: Dict[str, Dict[str, Any]] = {}  # filepath -> {"offset": int, "inode": int, "size": int}
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start file watcher background task."""
        if self.is_running:
            return
        self.is_running = True
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._scan_watch_dir()
        self.thread = threading.Thread(target=self._watch_loop, name="ulpf-file-watcher", daemon=True)
        self.thread.start()
        logger.info(f"File Collector started watching directory: {self.watch_dir.as_posix()}")

    def stop(self) -> None:
        """Stop file watcher."""
        self.is_running = False
        logger.info("File Collector stopped.")

    def _scan_watch_dir(self) -> None:
        """Scan directory for log files to watch."""
        if not self.watch_dir.exists():
            return
        for file_path in self.watch_dir.glob("*.log"):
            p_str = str(file_path.resolve())
            if p_str not in self.watched_files:
                self.watch_file(p_str)

    def watch_file(self, filepath: str) -> bool:
        """Add file path to watch list."""
        p = Path(filepath)
        if p.exists() and p.is_file():
            stat = p.stat()
            self.watched_files[str(p.resolve())] = {
                "offset": stat.st_size,
                "inode": getattr(stat, "st_ino", 0),
                "size": stat.st_size,
                "last_seen": time.time(),
            }
            return True
        return False

    def ingest_file_content(self, content: str, filename: str = "uploaded.log") -> List[Any]:
        """
        Process uploaded log file content (multiline/batch) line-by-line.
        Returns list of processed canonical events.
        """
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        results = []

        for line in lines:
            self.total_received += 1
            self.bytes_received += len(line.encode("utf-8"))

            ingress = RawIngress(
                connector_type="file_tail",
                source=f"file:{filename}",
                raw_text=line,
                transport_metadata={"filename": filename}
            )

            try:
                if self.pipeline:
                    ir_event = self.pipeline.process(line, source=f"file:{filename}")
                    self.total_accepted += 1
                    self.total_processed += 1
                    if self.event_callback:
                        self.event_callback(ir_event, source_name=f"file:{filename}")
                    results.append(ir_event)
                elif self.queue:
                    accepted, _ = self.queue.enqueue(ingress)
                    if accepted:
                        self.total_accepted += 1
                        self.total_processed += 1
                    else:
                        self.total_rejected += 1
            except Exception as e:
                self.total_errors += 1
                logger.error(f"[FileCollector] Error processing line from {filename}: {e}")

        return results

    def poll_files(self) -> None:
        """Synchronously poll all watched files for new data. Useful for unit testing."""
        self._scan_watch_dir()
        self._tail_all_watched_files()

    def _watch_loop(self) -> None:
        """Background file tailing loop."""
        while self.is_running:
            self._scan_watch_dir()
            self._tail_all_watched_files()

            time.sleep(1.0)

    def _tail_all_watched_files(self) -> None:
        """Core tail logic — called by both background loop and poll_files()."""
        for filepath, meta in list(self.watched_files.items()):
                p = Path(filepath)
                if not p.exists():
                    continue

                try:
                    stat = p.stat()
                    curr_size = stat.st_size
                    curr_inode = getattr(stat, "st_ino", 0)
                    last_offset = meta["offset"]
                    last_inode = meta["inode"]

                    # Rotation Detection: File shrunk or inode changed
                    if curr_size < last_offset or (last_inode and curr_inode != last_inode):
                        logger.info(f"[FileCollector] Log rotation detected on {filepath}")
                        last_offset = 0
                        meta["inode"] = curr_inode

                    if curr_size > last_offset:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(last_offset)
                            new_lines = f.readlines()
                            meta["offset"] = f.tell()
                            meta["size"] = curr_size

                        for raw_line in new_lines:
                            line_clean = raw_line.strip()
                            if not line_clean:
                                continue

                            self.total_received += 1
                            self.bytes_received += len(line_clean.encode("utf-8"))

                            ingress = RawIngress(
                                connector_type="file_tail",
                                source=f"file:{p.name}",
                                raw_text=line_clean,
                                transport_metadata={"filepath": filepath, "offset": meta["offset"]}
                            )

                            if self.queue:
                                accepted, reason = self.queue.enqueue(ingress)
                                if accepted:
                                    self.total_accepted += 1
                                    self.total_processed += 1
                                else:
                                    self.total_rejected += 1
                            elif self.pipeline:
                                ir_event = self.pipeline.process(line_clean, source=f"file:{p.name}")
                                self.total_accepted += 1
                                self.total_processed += 1
                                if self.event_callback:
                                    self.event_callback(ir_event, source_name=f"file:{p.name}")
                            elif self.event_callback:
                                # Direct callback mode (no pipeline / queue) — used in testing
                                self.total_accepted += 1
                                self.total_processed += 1
                                self.event_callback(ingress)

                except Exception as e:
                    logger.error(f"[FileCollector] Error reading watched file {filepath}: {e}")

    def get_status(self) -> Dict[str, Any]:
        status = super().get_status()
        status.update({
            "watch_dir": str(self.watch_dir),
            "watched_files_count": len(self.watched_files),
            "watched_files": list(self.watched_files.keys()),
        })
        return status
