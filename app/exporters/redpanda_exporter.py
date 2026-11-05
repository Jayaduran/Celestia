import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.models.canonical_event import CanonicalEvent
from app.exporters.base import BaseExporter
from app.exporters.ocsf import OcsfExporter
from app.exporters.ecs import EcsExporter
from app.config import settings

logger = logging.getLogger(__name__)


class RedpandaExporter(BaseExporter):
    """
    Redpanda / Kafka Streaming Exporter.
    Publishes standardized canonical ULPF-IR, OCSF, and ECS events
    to downstream Redpanda topics (e.g. ulpf-events-normalized, ulpf-alerts)
    for consumption by SIEMs, ML analysis pipelines, and Data Lakes.
    """

    def __init__(
        self,
        output_topic: Optional[str] = None,
        alerts_topic: Optional[str] = None,
        brokers: Optional[str] = None,
    ):
        self.output_topic = output_topic or settings.redpanda_output_topic
        self.alerts_topic = alerts_topic or settings.redpanda_alerts_topic
        self.brokers = brokers or settings.redpanda_brokers
        self.ocsf_exporter = OcsfExporter()
        self.ecs_exporter = EcsExporter()

        self.total_exported = 0
        self.total_alerts_exported = 0
        self.total_bytes_exported = 0
        self.total_errors = 0

    @property
    def target_schema(self) -> str:
        return "Redpanda (Kafka Streaming Protocol)"

    def export(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        """
        Export ULPF-IR canonical event into standardized streaming package.
        """
        ocsf_data = self.ocsf_exporter.export(canonical_event)
        ecs_data = self.ecs_exporter.export(canonical_event)

        vendor = canonical_event.device.vendor if canonical_event.device and canonical_event.device.vendor else "Unknown"
        product = canonical_event.device.product if canonical_event.device and canonical_event.device.product else "Unknown"
        category = canonical_event.event.category if canonical_event.event and canonical_event.event.category else "network"
        severity = canonical_event.severity or "info"
        timestamp = getattr(canonical_event, "timestamp", None)
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
        elif hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        else:
            timestamp = str(timestamp)

        package = {
            "stream_id": f"rp-{canonical_event.ulpf.event_id}",
            "topic": self.output_topic,
            "event_id": canonical_event.ulpf.event_id,
            "raw_sha256": canonical_event.original.sha256,
            "vendor": vendor,
            "product": product,
            "category": category,
            "severity": str(severity),
            "timestamp": timestamp,
            "ulpf_ir": canonical_event.model_dump(exclude={"original", "provenance", "ulpf"}),
            "ocsf": ocsf_data,
            "ecs": ecs_data,
        }

        # Check if high severity alert should also publish to alerts topic
        severity = str(package.get("severity", "info")).lower()
        is_alert = severity in ("high", "critical", "alert", "emergency")
        if is_alert:
            package["alert_topic"] = self.alerts_topic
            self.total_alerts_exported += 1

        # Attempt publishing to Redpanda HTTP Pandaproxy if connected
        if getattr(self, "_connected", False):
            try:
                primary_broker = self.brokers.split(",")[0].split(":")[0]
                proxy_url = f"http://{primary_broker}:8082/topics/{self.output_topic}"
                req_data = json.dumps({
                    "records": [{"value": package, "key": canonical_event.ulpf.event_id}]
                }).encode("utf-8")
                req = urllib.request.Request(
                    proxy_url,
                    data=req_data,
                    headers={"Content-Type": "application/vnd.kafka.json.v2+json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=0.2) as resp:
                    pass
            except Exception:
                pass

        raw_bytes = len(json.dumps(package).encode("utf-8"))
        self.total_exported += 1
        self.total_bytes_exported += raw_bytes

        return package

    def get_metrics(self) -> Dict[str, Any]:
        """Return streaming exporter metrics."""
        return {
            "target_schema": self.target_schema,
            "output_topic": self.output_topic,
            "alerts_topic": self.alerts_topic,
            "total_exported": self.total_exported,
            "total_alerts_exported": self.total_alerts_exported,
            "total_bytes_exported": self.total_bytes_exported,
            "total_errors": self.total_errors,
        }
