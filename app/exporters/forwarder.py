import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.models.canonical_event import CanonicalEvent
from app.exporters.ocsf import OcsfExporter
from app.exporters.ecs import EcsExporter

logger = logging.getLogger(__name__)


class MockSiemStore:
    """In-memory Mock SIEM / Data Lake store for demonstration."""

    def __init__(self, max_events: int = 500):
        self.events: List[Dict[str, Any]] = []
        self.max_events = max_events

    def add_event(self, event_data: Dict[str, Any]) -> None:
        self.events.insert(0, event_data)
        if len(self.events) > self.max_events:
            self.events.pop()

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.events[:limit]

    def clear(self) -> None:
        self.events.clear()


# Global Singleton Mock SIEM Store
mock_siem = MockSiemStore()


class LogForwarder:
    """
    Log Delivery & Forwarding Engine ("The Post Office Deliverer").
    Takes standardized ULPF-IR canonical events, generates OCSF/ECS export packages,
    and forwards them onward to downstream destinations (SIEM, Data Lake, ML Engine).
    """

    def __init__(self):
        self.ocsf_exporter = OcsfExporter()
        self.ecs_exporter = EcsExporter()
        self.total_forwarded = 0

    def forward(self, ir_event: CanonicalEvent, target_destination: str = "mock_siem") -> Dict[str, Any]:
        """
        Forward event to designated downstream target.
        """
        ocsf_data = self.ocsf_exporter.export(ir_event)
        ecs_data = self.ecs_exporter.export(ir_event)

        forwarded_package = {
            "forward_id": f"fw-{ir_event.ulpf.event_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "destination": target_destination,
            "status": "DELIVERED",
            "event_id": ir_event.ulpf.event_id,
            "raw_sha256": ir_event.original.sha256,
            "format": ir_event.original.format,
            "ocsf_payload": ocsf_data,
            "ecs_payload": ecs_data,
            "canonical_payload": ir_event.model_dump(exclude={"original", "provenance", "ulpf"}),
        }

        # Deliver to Mock SIEM store for dashboard visibility
        mock_siem.add_event(forwarded_package)
        self.total_forwarded += 1

        logger.info(f"Forwarded event {ir_event.ulpf.event_id} to downstream target '{target_destination}'")
        return forwarded_package
