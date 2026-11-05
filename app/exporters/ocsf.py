from typing import Dict, Any
from app.models.canonical_event import CanonicalEvent
from app.exporters.base import BaseExporter


class OcsfExporter(BaseExporter):
    """
    Translates ULPF-IR v1.0 into OCSF v1.1.0 (Class 4001: Network Connection Activity).
    """

    @property
    def target_schema(self) -> str:
        return "ocsf_v1.1.0"

    def _map_action_id(self, action: str) -> int:
        act = (action or "").lower()
        if act in ["allow", "accept", "pass"]:
            return 1  # Allowed
        elif act in ["deny", "drop", "block", "reject"]:
            return 2  # Denied
        return 99  # Other / Unknown

    def _map_severity_id(self, severity: Any) -> int:
        sev_str = str(severity or "").lower()
        if "crit" in sev_str or "high" in sev_str or sev_str in ["4", "5"]:
            return 4  # High/Critical
        elif "med" in sev_str or sev_str == "3":
            return 3  # Medium
        elif "low" in sev_str or sev_str == "2":
            return 2  # Low
        return 1  # Informational / Unknown

    def export(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        ir = canonical_event

        ocsf_dict: Dict[str, Any] = {
            "category_uid": 4,  # Network Activity
            "category_name": "Network Activity",
            "class_uid": 4001,  # Network Connection Activity
            "class_name": "Network Activity: Network Connection",
            "activity_id": 1,
            "action_id": self._map_action_id(ir.event.action),
            "action": ir.event.action or "unknown",
            "severity_id": self._map_severity_id(ir.severity),
            "status": ir.status,
            "time": ir.event.time or ir.original.sha256[:8],
            "src_endpoint": {
                "ip": ir.source.ip,
                "port": ir.source.port,
                "mac": ir.source.mac,
            },
            "dst_endpoint": {
                "ip": ir.destination.ip,
                "port": ir.destination.port,
                "mac": ir.destination.mac,
            },
            "connection_info": {
                "protocol_name": ir.network.protocol,
                "transport_name": ir.network.transport,
                "boundary": ir.network.ssid,
            },
            "device": {
                "vendor_name": ir.device.vendor,
                "product": {
                    "name": ir.device.product,
                },
                "hostname": ir.device.hostname,
            },
            "unmapped": ir.unmapped,
            "raw_data": ir.original.message,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "ULPF Engine", "version": "1.0.0"},
                "event_code": ir.event.id,
                "log_hash": ir.original.sha256,
            },
        }

        # Filter out null values for clean OCSF output
        return {k: v for k, v in ocsf_dict.items() if v is not None}
