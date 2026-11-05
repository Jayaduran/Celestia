from typing import Dict, Any
from app.models.canonical_event import CanonicalEvent
from app.exporters.base import BaseExporter


class EcsExporter(BaseExporter):
    """
    Translates ULPF-IR v1.0 into Elastic Common Schema (ECS v8.x).
    """

    @property
    def target_schema(self) -> str:
        return "ecs_v8.11.0"

    def export(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        ir = canonical_event

        ecs_dict: Dict[str, Any] = {
            "@timestamp": ir.event.time,
            "event": {
                "id": ir.ulpf.event_id,
                "category": [ir.event.category or "network"],
                "type": [ir.event.type or "connection"],
                "action": ir.event.action,
                "code": ir.event.id,
                "severity": ir.severity,
                "outcome": "success" if ir.event.action in ["allow", "accept", "pass"] else "failure",
            },
            "source": {
                "ip": ir.source.ip,
                "port": ir.source.port,
                "mac": ir.source.mac,
            },
            "destination": {
                "ip": ir.destination.ip,
                "port": ir.destination.port,
                "mac": ir.destination.mac,
            },
            "network": {
                "transport": ir.network.transport,
                "protocol": ir.network.protocol,
                "name": ir.network.ssid,
            },
            "observer": {
                "vendor": ir.device.vendor,
                "product": ir.device.product,
                "hostname": ir.device.hostname,
            },
            "rule": {
                "name": ir.rule.name,
                "id": ir.rule.id,
            },
            "user": {
                "name": ir.user.name,
            },
            "log": {
                "original": ir.original.message,
                "syslog": {"priority": ir.severity},
            },
            "related": {
                "ip": [ip for ip in [ir.source.ip, ir.destination.ip] if ip],
                "user": [ir.user.name] if ir.user.name else [],
            },
            "event_hash": ir.original.sha256,
        }

        # Recursively remove None or empty dict entries
        return self._clean_dict(ecs_dict)

    def _clean_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        clean: Dict[str, Any] = {}
        for k, v in d.items():
            if v is None:
                continue
            if isinstance(v, dict):
                sub = self._clean_dict(v)
                if sub:
                    clean[k] = sub
            elif isinstance(v, list) and not v:
                continue
            else:
                clean[k] = v
        return clean
