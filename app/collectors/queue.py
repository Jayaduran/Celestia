import time
import asyncio
import logging
import redis
from typing import Optional, Callable, Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from app.collectors.ingress import RawIngress
from app.config import settings

logger = logging.getLogger(__name__)

# Global worker state
_worker_pipeline = None

def _init_worker():
    """Initializer for executor to load heavy models once per process/thread."""
    global _worker_pipeline
    try:
        from app.pipeline import UlpfPipeline
        _worker_pipeline = UlpfPipeline()
    except Exception as e:
        print(f"Failed to initialize worker pipeline: {e}")

def _process_batch_worker(batch: List[Tuple[str, str]]) -> List[Any]:
    """Worker log processor for micro-batches."""
    global _worker_pipeline
    if not _worker_pipeline:
        try:
            from app.pipeline import UlpfPipeline
            _worker_pipeline = UlpfPipeline()
        except Exception:
            return [{"__dlq_error__": "Pipeline init failed", "raw": msg, "source": src} for msg, src in batch]
    
    results = []
    for raw_text, source in batch:
        try:
            results.append(_worker_pipeline.process(raw_message=raw_text, source=source))
        except Exception as e:
            results.append({"__dlq_error__": str(e), "raw": raw_text, "source": source})
    return results


class AsyncIngestionQueue:
    """
    High-Throughput Async Ingestion Queue & Multiprocessing Dispatcher.
    Buffers raw log items from network connectors via asyncio, applies rate limiting,
    and feeds an Executor for high-speed concurrent parsing.
    """

    def __init__(
        self,
        max_size: Optional[int] = None,
        max_eps: Optional[int] = None,
        worker_count: Optional[int] = None,
        pipeline: Optional[Any] = None,
        event_callback: Optional[Callable] = None,
        redpanda_collector: Optional[Any] = None,
    ):
        self.max_size = max_size or settings.ingress_queue_max_size
        self.max_eps = max_eps or settings.max_events_per_second
        
        # Dynamically scale workers to prevent over-threading on limited cores
        if worker_count is None:
            import os
            assigned_workers = int(os.getenv("WORKERS", "0"))
            cores = os.cpu_count() or 4
            if assigned_workers > 0:
                self.worker_count = assigned_workers
            else:
                self.worker_count = min(16, max(1, cores // 4))
        else:
            self.worker_count = worker_count
            
        self.pipeline = pipeline
        self.event_callback = event_callback
        self.redpanda_collector = redpanda_collector

        self._queue: Optional[asyncio.Queue] = None
        self._is_running = False
        self._consumer_task: Optional[asyncio.Task] = None
        self._executor: Optional[Any] = None

        # Rate Limiting State
        self._window_start = time.time()
        self._client_window_counts = {}
        self.redis_client = None
        if settings.redis_enabled:
            try:
                self.redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info(f"Redis Rate Limiter connected via {settings.redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis for rate limiting: {e}. Falling back to local global limiter.")
                self.redis_client = None

        # Metrics
        self.total_enqueued = 0
        self.total_processed = 0
        self.total_dropped_rate_limit = 0
        self.total_dropped_backpressure = 0
        self.total_errors = 0
        self.total_redpanda_mirrored = 0
        self.total_dlq_routed = 0
        
        # DLQ Init
        import os
        from pathlib import Path
        self.dlq_dir = Path(settings.storage_dir) / "dlq"
        self.dlq_dir.mkdir(parents=True, exist_ok=True)
        self.dlq_file = self.dlq_dir / "dlq_events.log"

    def start(self) -> None:
        """Start the async queue and consumer loop."""
        if self._is_running:
            return

        self._queue = asyncio.Queue(maxsize=self.max_size)
        self._executor = ThreadPoolExecutor(
            max_workers=self.worker_count, 
            initializer=_init_worker
        )
        
        self._is_running = True
        self._consumer_tasks = []

        try:
            loop = asyncio.get_running_loop()
            for _ in range(self.worker_count * 2):
                self._consumer_tasks.append(loop.create_task(self._consumer_loop()))
            logger.info(f"AsyncIngestionQueue started with {self.worker_count} workers.")
        except RuntimeError:
            import threading
            self._thread_loop = asyncio.new_event_loop()
            def _run():
                asyncio.set_event_loop(self._thread_loop)
                for _ in range(self.worker_count * 2):
                    self._consumer_tasks.append(self._thread_loop.create_task(self._consumer_loop()))
                self._thread_loop.run_forever()
            self._bg_thread = threading.Thread(target=_run, daemon=True)
            self._bg_thread.start()
            time.sleep(0.05)
            logger.info(f"AsyncIngestionQueue started with {self.worker_count} workers (threaded loop).")

    def stop(self) -> None:
        """Gracefully stop queue and executor."""
        self._is_running = False
        if hasattr(self, '_consumer_tasks') and self._consumer_tasks:
            for task in self._consumer_tasks:
                try:
                    task.cancel()
                except Exception:
                    pass
        elif hasattr(self, '_consumer_task') and self._consumer_task:
            try:
                self._consumer_task.cancel()
            except Exception:
                pass
        if hasattr(self, "_thread_loop") and self._thread_loop and self._thread_loop.is_running():
            try:
                self._thread_loop.call_soon_threadsafe(self._thread_loop.stop)
            except Exception:
                pass
        if self._executor:
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass
        logger.info("AsyncIngestionQueue stopped.")

    def set_worker_count(self, new_count: int) -> None:
        """Hot-swap worker count (restarts executor if running)."""
        if new_count < 1:
            new_count = 1
        
        if self.worker_count == new_count:
            return
            
        self.worker_count = new_count
        if self._is_running and self._executor:
            self._executor.shutdown(wait=False)
            self._executor = ThreadPoolExecutor(
                max_workers=self.worker_count, 
                initializer=_init_worker
            )
            
            if hasattr(self, '_consumer_tasks') and self._consumer_tasks:
                for task in self._consumer_tasks:
                    task.cancel()
            self._consumer_tasks = []
            try:
                loop = asyncio.get_running_loop()
                for _ in range(self.worker_count * 2):
                    self._consumer_tasks.append(loop.create_task(self._consumer_loop()))
            except RuntimeError:
                if hasattr(self, "_thread_loop") and self._thread_loop:
                    for _ in range(self.worker_count * 2):
                        self._consumer_tasks.append(self._thread_loop.create_task(self._consumer_loop()))
                
            logger.info(f"Scaled workers to {new_count}")

    def _check_rate_limit(self, client_id: str = "global") -> bool:
        """Redis-backed per-client rate limit check with local global fallback."""
        if self.redis_client:
            try:
                # Redis-backed isolated rate limiting (per client IP/source)
                key = f"ulpf:ratelimit:{client_id}"
                current_count = self.redis_client.incr(key)
                if current_count == 1:
                    self.redis_client.expire(key, 1) # 1-second fixed window
                
                if current_count > self.max_eps:
                    return False
                return True
            except Exception as e:
                # Fallback to local rate limiting if Redis is down
                logger.error(f"Redis rate limiting error: {e}")
                pass

        now = time.time()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._client_window_counts = {}
        
        current_count = self._client_window_counts.get(client_id, 0)
        if current_count >= self.max_eps:
            return False
            
        self._client_window_counts[client_id] = current_count + 1
        return True

    def enqueue(self, ingress: RawIngress) -> Tuple[bool, str]:
        """
        Non-blocking enqueue for asyncio network callbacks.
        """
        if not self._is_running or not self._queue:
            return False, "STOPPED"

        client_id = ingress.source or "unknown"
        if not self._check_rate_limit(client_id):
            self.total_dropped_rate_limit += 1
            return False, "RATE_LIMIT_EXCEEDED"

        try:
            if settings.redpanda_enabled and self.redpanda_collector and ingress.connector_type != "redpanda":
                try:
                    self.redpanda_collector.produce(raw_message=ingress.raw_text, source=ingress.source)
                    self.total_redpanda_mirrored += 1
                    # Skip local processing to avoid duplication; Redpanda consumer will ingest it.
                    return True, "PRODUCED_TO_REDPANDA"
                except Exception:
                    # Fallback to local queue if produce fails
                    pass

            if hasattr(self, "_thread_loop") and self._thread_loop and self._thread_loop.is_running():
                self._thread_loop.call_soon_threadsafe(self._queue.put_nowait, ingress)
            else:
                self._queue.put_nowait(ingress)
            self.total_enqueued += 1

            # Non-blocking zero-copy staging to Kosmoporos Temp Storage buffer
            try:
                from app.storage.temp_storage import get_temp_storage
                get_temp_storage().stage_raw_log(
                    event_id=getattr(ingress, "ingress_id", str(time.time())),
                    raw_payload=ingress.raw_text,
                    source=ingress.source,
                    metadata=getattr(ingress, "transport_metadata", None),
                )
            except Exception:
                pass

            return True, "ACCEPTED"
        except asyncio.QueueFull:
            self.total_dropped_backpressure += 1
            return False, "QUEUE_FULL_BACKPRESSURE"

    async def _consumer_loop(self) -> None:
        """Async loop consuming from queue and dispatching micro-batches to Executor."""
        loop = asyncio.get_running_loop()
        batch_size = 500
        
        while self._is_running and self._queue:
            try:
                batch = []
                # Block for the first item
                first_item = await self._queue.get()
                batch.append((first_item.raw_text, first_item.source, first_item))
                
                # Drain up to batch_size synchronously
                while len(batch) < batch_size:
                    try:
                        item = self._queue.get_nowait()
                        batch.append((item.raw_text, item.source, item))
                    except asyncio.QueueEmpty:
                        break
                
                worker_payload = [(raw, src) for raw, src, _ in batch]
                
                try:
                    # Dispatch entire batch to worker process
                    results = await loop.run_in_executor(
                        self._executor, 
                        _process_batch_worker, 
                        worker_payload
                    )

                    for i, ir_event in enumerate(results):
                        original_item = batch[i][2]
                        if ir_event:
                            if isinstance(ir_event, dict) and "__dlq_error__" in ir_event:
                                self._route_to_dlq(original_item, ir_event["__dlq_error__"])
                            else:
                                if hasattr(ir_event, "original") and original_item.transport_metadata:
                                    setattr(ir_event.original, "transport", original_item.connector_type)
                                    client_ip = original_item.transport_metadata.get("client_ip")
                                    if client_ip and hasattr(ir_event, "source") and (not ir_event.source.ip or ir_event.source.ip in ("N/A", "0.0.0.0")):
                                        ir_event.source.ip = client_ip

                                if self.event_callback:
                                    def _run_cb(ev=ir_event, src=original_item.source):
                                        self.event_callback(ev, source_name=src)
                                    await loop.run_in_executor(None, _run_cb)

                        self.total_processed += 1
                except Exception as e:
                    self.total_errors += len(batch)
                    logger.error(f"[AsyncIngestionQueue] Batch processing error: {e}")
                    for _, _, item in batch:
                        self._route_to_dlq(item, str(e))
                finally:
                    for _ in batch:
                        self._queue.task_done()
                    
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def _route_to_dlq(self, item: RawIngress, error_msg: str) -> None:
        """Appends failed event to DLQ file."""
        self.total_dlq_routed += 1
        try:
            import json
            from datetime import datetime, timezone
            dlq_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": item.source,
                "connector_type": item.connector_type,
                "error": error_msg,
                "raw_text": item.raw_text,
            }
            with open(self.dlq_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(dlq_record) + "\n")
        except Exception as e:
            logger.error(f"[DLQ] Failed to write to DLQ: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "queue_depth": self._queue.qsize() if self._queue else 0,
            "max_queue_size": self.max_size,
            "max_eps_limit": self.max_eps,
            "worker_threads": self.worker_count,
            "is_running": self._is_running,
            "total_enqueued": self.total_enqueued,
            "total_processed": self.total_processed,
            "total_dropped_rate_limit": self.total_dropped_rate_limit,
            "total_dropped_backpressure": self.total_dropped_backpressure,
            "total_redpanda_mirrored": self.total_redpanda_mirrored,
            "total_errors": self.total_errors,
            "total_dlq_routed": self.total_dlq_routed,
        }

# Maintain backwards compatibility name for routes.py imports
IngestionQueue = AsyncIngestionQueue
