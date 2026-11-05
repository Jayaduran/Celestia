from typing import Dict, Any


class OcsfExporter:
    """Translates CanonicalEvent into OCSF v1.1.0 JSON format."""

    @property
    def target_schema(self) -> str:
        return "ocsf_v1.1.0"

    def _map_action_id(self, action: str) -> int:
        act = (action or "").lower()
        if act in ["allow", "accept", "pass"]:
            return 1
        elif act in ["deny", "drop", "block", "reject"]:
            return 2
        return 99

    def _map_severity_id(self, severity: Any) -> int:
        sev_str = str(severity or "").lower()
        if "crit" in sev_str or "high" in sev_str or sev_str in ["4", "5"]:
            return 4
        elif "med" in sev_str or sev_str == "3":
            return 3
        elif "low" in sev_str or sev_str == "2":
            return 2
        return 1

    def export(self, canonical_event: Any) -> Dict[str, Any]:
        ir = canonical_event
        src = getattr(ir, "source", None)
        dst = getattr(ir, "destination", None)
        net = getattr(ir, "network", None)
        evt = getattr(ir, "event", None)

        return {
            "category_uid": 4,
            "category_name": "Network Activity",
            "class_uid": 4001,
            "class_name": "Network Activity: Network Connection",
            "activity_id": 1,
            "action_id": self._map_action_id(getattr(evt, "action", None)),
            "action": getattr(evt, "action", "unknown") or "unknown",
            "severity_id": self._map_severity_id(getattr(ir, "severity", None)),
            "status": getattr(ir, "status", "success"),
            "src_endpoint": {
                "ip": getattr(src, "ip", None),
                "port": getattr(src, "port", None),
            },
            "dst_endpoint": {
                "ip": getattr(dst, "ip", None),
                "port": getattr(dst, "port", None),
            },
            "connection_info": {
                "protocol_name": getattr(net, "protocol", None),
                "transport_name": getattr(net, "transport", None),
            },
        }
