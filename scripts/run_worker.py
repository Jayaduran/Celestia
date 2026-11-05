import time
import signal
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

MAIN_DIR = Path(__file__).resolve().parent.parent / "main"
if str(MAIN_DIR) not in sys.path:
    sys.path.insert(0, str(MAIN_DIR))

from app.pipeline import UlpfPipeline
from app.storage.persistence import PersistenceManager
from app.collectors.redpanda_collector import RedpandaCollector
from app.exporters.redpanda_exporter import RedpandaExporter
from app.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("ulpf-worker")

is_running = True


def handle_shutdown(signum, frame):
    global is_running
    logger.info(f"Received termination signal ({signum}). Initiating graceful shutdown...")
    is_running = False


def main():
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    logger.info("=" * 60)
    logger.info("        ULPF DISTRIBUTED WORKER ENGINE (SCALE-OUT)")
    logger.info("=" * 60)
    logger.info(f"Connecting to Redpanda Brokers: {settings.redpanda_brokers}")
    logger.info(f"Subscribing to Input Topic:    {settings.redpanda_input_topic}")
    logger.info(f"Publishing to Output Topic:   {settings.redpanda_output_topic}")
    logger.info(f"Consumer Group:                {settings.redpanda_consumer_group}")
    logger.info("=" * 60)

    pipeline = UlpfPipeline()
    persistence = PersistenceManager()
    exporter = RedpandaExporter()

    def process_and_export(ir_event, source_name="redpanda-stream"):
        try:
            # 1. Persist to MinIO / SQLite / OpenSearch
            persistence.persist_event(ir_event, source=source_name)
            # 2. Export canonical stream to Redpanda normalized topic
            exporter.export(ir_event)
        except Exception as e:
            logger.error(f"Worker processing error: {e}")

    collector = RedpandaCollector(
        pipeline=pipeline,
        event_callback=process_and_export
    )

    collector.start()
    logger.info("Worker consumer thread online. Processing streaming logs...")

    last_report = time.time()
    while is_running:
        time.sleep(1)
        if time.time() - last_report >= 30:
            status = collector.get_status()
            logger.info(
                f"[Worker Telemetry] Consumed: {status['messages_consumed']:,} msgs ({status['bytes_consumed']:,} bytes) | "
                f"Exported: {exporter.total_exported:,} msgs | Connected: {status['connected']}"
            )
            last_report = time.time()

    collector.stop()
    logger.info("Worker stopped successfully.")


if __name__ == "__main__":
    main()
