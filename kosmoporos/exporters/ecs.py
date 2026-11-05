from typing import Dict, Any


class EcsExporter:
    """Translates CanonicalEvent into Elastic Common Schema (ECS v8.x) JSON format."""

    @property
    def target_schema(self) -> str:
        return "ecs_v8.11.0"

    def export(self, canonical_event: Any) -> Dict[str, Any]:
        ir = canonical_event
        src = getattr(ir, "source", None)
        dst = getattr(ir, "destination", None)
        net = getattr(ir, "network", None)
        evt = getattr(ir, "event", None)
        dev = getattr(ir, "device", None)
        rule = getattr(ir, "rule", None)
        user = getattr(ir, "user", None)
        orig = getattr(ir, "original", None)
        ulpf = getattr(ir, "ulpf", None)

        action = getattr(evt, "action", "") or ""

        return {
            "ecs": {"version": "8.11.0"},
            "@timestamp": getattr(evt, "time", None),
            "event": {
                "id": getattr(ulpf, "event_id", None),
                "category": [getattr(evt, "category", "network") or "network"],
                "type": [getattr(evt, "type", "connection") or "connection"],
                "action": action,
                "code": getattr(evt, "id", None),
                "severity": getattr(ir, "severity", None),
                "outcome": "success" if action in ("allow", "accept", "pass") else "failure",
            },
            "source": {
                "ip": getattr(src, "ip", None),
                "port": getattr(src, "port", None),
                "mac": getattr(src, "mac", None),
            },
            "destination": {
                "ip": getattr(dst, "ip", None),
                "port": getattr(dst, "port", None),
                "mac": getattr(dst, "mac", None),
            },
            "network": {
                "transport": getattr(net, "transport", None),
                "protocol": getattr(net, "protocol", None),
                "name": getattr(net, "ssid", None),
            },
            "observer": {
                "vendor": getattr(dev, "vendor", None),
                "product": getattr(dev, "product", None),
                "hostname": getattr(dev, "hostname", None),
            },
            "rule": {
                "name": getattr(rule, "name", None),
                "id": getattr(rule, "id", None),
            },
            "user": {
                "name": getattr(user, "name", None),
            },
            "log": {
                "original": getattr(orig, "message", None),
                "syslog": {"priority": getattr(ir, "severity", None)},
            },
            "related": {
                "ip": [ip for ip in [getattr(src, "ip", None), getattr(dst, "ip", None)] if ip],
                "user": [getattr(user, "name", None)] if getattr(user, "name", None) else [],
            },
            "event_hash": getattr(orig, "sha256", ""),
        }
