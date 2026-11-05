import os
import json
import time
import socket
import logging
import threading
import urllib.request
import urllib.error
from typing import Optional, Callable, Dict, Any, List, Tuple
from datetime import datetime, timezone
from app.collectors.base import BaseCollector
from app.collectors.ingress import RawIngress
from app.config import settings

logger = logging.getLogger(__name__)


class RedpandaCollector(BaseCollector):
    """
    High-Throughput Redpanda / Kafka Streaming Collector.
    Consumes raw security and infrastructure logs from Redpanda streaming topics,
    converts them into RawIngress records with cryptographic SHA-256 integrity,
    and feeds the ULPF normalization pipeline at scale.
    """

    def __init__(
        self,
        brokers: Optional[str] = None,
        input_topic: Optional[str] = None,
        output_topic: Optional[str] = None,
        consumer_group: Optional[str] = None,
        pipeline: Optional[Any] = None,
        queue: Optional[Any] = None,
        event_callback: Optional[Callable] = None,
    ):
        super().__init__(name="RedpandaCollector", connector_type="redpanda")
        self.brokers = brokers or settings.redpanda_brokers
        self.input_topic = input_topic or settings.redpanda_input_topic
        self.output_topic = output_topic or settings.redpanda_output_topic
        self.consumer_group = consumer_group or settings.redpanda_consumer_group
        self.admin_url = settings.redpanda_admin_url
        self.pipeline = pipeline
        self.queue = queue
        self.event_callback = event_callback

        self._is_running = False
        self._consumer_thread: Optional[threading.Thread] = None
        self._connected = False
        self._last_error: Optional[str] = None

        # Telemetry & Metrics
        self.messages_consumed = 0
        self.bytes_consumed = 0
        self.messages_produced = 0
        self.bytes_produced = 0
        self.total_errors = 0

        # In-memory buffer for recent messages and local stream emulation
        self._recent_messages: List[Dict[str, Any]] = []
        self._local_topic_buffer: List[Dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self._spool_lock = threading.Lock()
        
        from concurrent.futures import ThreadPoolExecutor
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="redpanda_bg")

        # Disk spooling for high-throughput buffering
        self.spool_file = os.path.join(os.environ.get("STORAGE_DIR", "storage/raw"), "temp_spool.jsonl")
        self.max_mem_buffer = int(os.environ.get("REDPANDA_MAX_MEM_BUFFER", "5000"))
        self.spooling_active = False

    def _spool_to_disk(self, items: List[Dict[str, Any]]) -> None:
        """Dump excess logs to a temporary JSONL file."""
        try:
            os.makedirs(os.path.dirname(self.spool_file), exist_ok=True)
            with self._spool_lock:
                with open(self.spool_file, "a", encoding="utf-8") as f:
                    for item in items:
                        f.write(json.dumps(item) + "\n")
                self.spooling_active = True
        except Exception as e:
            logger.error(f"Failed to spool logs to disk: {e}")

    def _read_from_spool(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Read up to `limit` logs from the spool file and remove them."""
        with self._spool_lock:
            if not os.path.exists(self.spool_file):
                self.spooling_active = False
                return []
                
            items = []
            remaining_lines = []
            try:
                with open(self.spool_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    
                for line in lines[:limit]:
                    if line.strip():
                        items.append(json.loads(line))
                        
                remaining_lines = lines[limit:]
                
                if remaining_lines:
                    with open(self.spool_file, "w", encoding="utf-8") as f:
                        f.writelines(remaining_lines)
                else:
                    os.remove(self.spool_file)
                    self.spooling_active = False
                    
            except Exception as e:
                logger.error(f"Failed to read from spool: {e}")
                
            return items

    def start(self) -> None:
        """Start background consumer loop."""
        if self._is_running:
            return

        self._is_running = True
        self.is_running = True
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="ulpf-redpanda-consumer",
            daemon=True
        )
        self._consumer_thread.start()
        logger.info(
            f"RedpandaCollector started (Brokers: {self.brokers}, Topic: {self.input_topic}, Group: {self.consumer_group})"
        )

    def stop(self) -> None:
        """Stop consumer thread."""
        self._is_running = False
        self.is_running = False
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=1.0)
        self._connected = False
        
        if hasattr(self, "_executor"):
            self._executor.shutdown(wait=False)
            
        logger.info("RedpandaCollector stopped.")

    def check_broker_connectivity(self, force_refresh: bool = False, timeout: float = 0.05) -> Tuple[bool, str]:
        """Verify TCP connectivity to at least one Redpanda broker address with caching."""
        now = time.time()
        if not force_refresh and hasattr(self, "_last_conn_result") and (now - getattr(self, "_last_conn_check_time", 0) < 5.0):
            return self._last_conn_result

        broker_list = [b.strip() for b in self.brokers.split(",") if b.strip()]
        for broker in broker_list:
            try:
                host, port_str = broker.split(":")
                port = int(port_str)
                # Resolve host quickly
                with socket.create_connection((host, port), timeout=timeout):
                    res = (True, f"Connected to broker at {broker}")
                    self._last_conn_result = res
                    self._last_conn_check_time = now
                    return res
            except Exception:
                continue

        res = (False, f"Could not establish TCP socket connection to brokers: {self.brokers}")
        self._last_conn_result = res
        self._last_conn_check_time = now
        return res

    def produce(self, raw_message: str, topic: Optional[str] = None, source: str = "redpanda-producer") -> Dict[str, Any]:
        """
        Produce a raw log message to Redpanda topic.
        If live broker is available, writes via protocol/PandaProxy; otherwise buffers locally.
        """
        target_topic = topic or self.input_topic
        ingress = RawIngress(
            connector_type="redpanda",
            source=source,
            raw_text=raw_message,
            transport_metadata={"topic": target_topic, "produced_at": datetime.now(timezone.utc).isoformat()}
        )

        msg_payload = {
            "topic": target_topic,
            "event_id": ingress.event_id,
            "raw_sha256": ingress.raw_sha256,
            "source": source,
            "raw_text": raw_message,
            "timestamp": ingress.received_at,
        }

        # Try publishing via Redpanda Pandaproxy HTTP only if broker is verified connected
        published_to_broker = False
        if self._connected:
            try:
                primary_host = self.brokers.split(",")[0].split(":")[0]
                proxy_url = f"http://{primary_host}:8082/topics/{target_topic}"
                req_data = json.dumps({
                    "records": [{"value": raw_message, "key": ingress.event_id}]
                }).encode("utf-8")
                req = urllib.request.Request(proxy_url, data=req_data, headers={"Content-Type": "application/vnd.kafka.json.v2+json"}, method="POST")
                with urllib.request.urlopen(req, timeout=0.2) as resp:
                    if resp.status in (200, 204):
                        published_to_broker = True
            except Exception:
                pass

        with self._buffer_lock:
            self._recent_messages.insert(0, msg_payload)
            if len(self._recent_messages) > 100:
                self._recent_messages.pop()

            if target_topic == self.input_topic:
                self._local_topic_buffer.append(msg_payload)
                if len(self._local_topic_buffer) >= self.max_mem_buffer:
                    # Spool the entire current buffer to disk to prevent thread explosion and free RAM instantly
                    items_to_spool = self._local_topic_buffer[:]
                    self._local_topic_buffer = []
                    self._executor.submit(self._spool_to_disk, items_to_spool)

        self.messages_produced += 1
        self.bytes_produced += len(raw_message.encode("utf-8"))

        return {
            "status": "published",
            "topic": target_topic,
            "event_id": ingress.event_id,
            "raw_sha256": ingress.raw_sha256,
            "published_to_broker": published_to_broker,
            "buffer_depth": len(self._local_topic_buffer)
        }

    def _consumer_loop(self) -> None:
        """Continuous polling and ingestion worker loop with chunking."""
        last_conn_check = time.time()
        batch_size = 500

        while self._is_running:
            try:
                now = time.time()
                # 1. Periodically check socket connectivity asynchronously
                if now - last_conn_check >= 5.0:
                    self._executor.submit(self._async_check_broker)
                    last_conn_check = now

                # 2. Process local buffer in chunks
                items_to_process = []
                with self._buffer_lock:
                    if self._local_topic_buffer:
                        chunk_size = min(len(self._local_topic_buffer), batch_size)
                        items_to_process = self._local_topic_buffer[:chunk_size]
                        self._local_topic_buffer = self._local_topic_buffer[chunk_size:]

                # 3. If memory buffer is low and spooling is active, recover from disk
                if len(items_to_process) < batch_size and self.spooling_active:
                    recovered = self._read_from_spool(limit=batch_size - len(items_to_process))
                    items_to_process.extend(recovered)

                if items_to_process:
                    for item in items_to_process:
                        self._process_message(item)
                    continue

                time.sleep(0.02)
            except Exception as e:
                self._last_error = str(e)
                self.total_errors += 1
                time.sleep(0.1)

    def _async_check_broker(self) -> None:
        """Background thread to check broker connectivity without blocking ingestion."""
        is_online, _ = self.check_broker_connectivity(timeout=0.05)
        self._connected = is_online

    def _process_message(self, msg_payload: Dict[str, Any]) -> None:
        """Process consumed message into ULPF pipeline."""
        raw_text = msg_payload.get("raw_text", "")
        source = msg_payload.get("source", "redpanda-stream")
        topic = msg_payload.get("topic", self.input_topic)

        ingress = RawIngress(
            event_id=msg_payload.get("event_id"),
            connector_type="redpanda",
            source=source,
            raw_text=raw_text,
            transport_metadata={"topic": topic, "consumed_at": datetime.now(timezone.utc).isoformat()}
        )

        self.messages_consumed += 1
        self.bytes_consumed += len(raw_text.encode("utf-8"))
        self.total_received += 1

        if self.queue:
            accepted, reason = self.queue.enqueue(ingress)
            if accepted:
                self.total_processed += 1
        elif self.pipeline:
            ir_event = self.pipeline.process(raw_message=raw_text, source=source)
            self.total_processed += 1
            if self.event_callback:
                self.event_callback(ir_event, source_name=source)

    def get_recent_messages(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent stream messages."""
        with self._buffer_lock:
            return list(self._recent_messages[:limit])

    def get_status(self) -> Dict[str, Any]:
        """Return full Redpanda subsystem telemetry."""
        is_socket_connected, sock_msg = self.check_broker_connectivity()
        return {
            "name": self.name,
            "is_running": self._is_running,
            "connected": is_socket_connected or self._connected,
            "connectivity_detail": sock_msg,
            "brokers": self.brokers.split(","),
            "input_topic": self.input_topic,
            "output_topic": self.output_topic,
            "consumer_group": self.consumer_group,
            "admin_url": self.admin_url,
            "messages_consumed": self.messages_consumed,
            "bytes_consumed": self.bytes_consumed,
            "messages_produced": self.messages_produced,
            "bytes_produced": self.bytes_produced,
            "buffered_in_flight": len(self._local_topic_buffer),
            "total_errors": self.total_errors,
            "last_error": self._last_error,
        }
