import json
import re
from typing import Dict, Any
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class SuricataParser(BaseParser):
    """
    Dedicated Parser for Suricata EVE JSON and Snort IDS / IPS / EDR network security events.
    Extracts alert signatures, MITRE attack indicators, flow metrics, and packet verdicts.
    """

    @property
    def parser_name(self) -> str:
        return "suricata_eve"

    # Snort / Suricata Fast Alert format regex
    SNORT_FAST_PATTERN = re.compile(
        r'\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*([^\[]+)\s*\[\*\*\](?:\s*\[Classification:\s*([^\]]+)\])?(?:\s*\[Priority:\s*(\d+)\])?\s*\{([a-zA-Z0-9]+)\}\s*([0-9.]+)(?::(\d+))?\s*->\s*([0-9.]+)(?::(\d+))?'
    )

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        # 1. Suricata EVE JSON
        if (msg.startswith("{") and msg.endswith("}")) or ('"event_type"' in msg and '"alert"' in msg):
            try:
                data = json.loads(msg)
                alert_obj = data.get("alert", {})
                event_type = data.get("event_type", "alert")

                # Map Suricata integer severity (1 = high/critical, 2 = medium, 3 = low)
                sev_int = alert_obj.get("severity", 2)
                sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
                severity_str = sev_map.get(sev_int, "medium")

                fields: Dict[str, Any] = {
                    "vendor": "OISF / Suricata",
                    "product": "Suricata Network Threat Engine",
                    "event_type": event_type,
                    "flow_id": data.get("flow_id"),
                    "src_ip": data.get("src_ip"),
                    "src_port": data.get("src_port"),
                    "dst_ip": data.get("dest_ip") or data.get("dst_ip"),
                    "dst_port": data.get("dest_port") or data.get("dst_port"),
                    "protocol": (data.get("proto") or "tcp").lower(),
                    "app_proto": data.get("app_proto"),
                    "in_iface": data.get("in_iface"),
                    "threat_name": alert_obj.get("signature", data.get("payload_printable")),
                    "threat_category": alert_obj.get("category", "Network Intrusion"),
                    "signature_id": alert_obj.get("signature_id"),
                    "signature_rev": alert_obj.get("rev"),
                    "severity": severity_str,
                    "action": alert_obj.get("action", "alert"),
                }

                # Normalize Action
                act = str(fields["action"]).lower()
                if act in ("blocked", "drop", "dropped", "reject"):
                    fields["action"] = "deny"
                elif act in ("allowed", "pass"):
                    fields["action"] = "allow"
                else:
                    fields["action"] = "alert"

                if "http" in data:
                    fields["http"] = data["http"]
                if "tls" in data:
                    fields["tls"] = data["tls"]

                return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)
            except Exception:
                pass

        # 2. Snort / Suricata Fast Alert format
        m_snort = self.SNORT_FAST_PATTERN.search(msg)
        if m_snort:
            gid, sid, rev, sig_name, classification, priority, proto, src_ip, src_port, dst_ip, dst_port = m_snort.groups()
            prio_int = int(priority) if priority else 2
            sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}

            fields = {
                "vendor": "Snort / Sourcefire",
                "product": "Snort Network IDS/IPS",
                "signature_id": f"{gid}:{sid}:{rev}",
                "threat_name": sig_name.strip(),
                "threat_category": (classification or "Intrusion Attempt").strip(),
                "severity": sev_map.get(prio_int, "medium"),
                "protocol": proto.lower(),
                "src_ip": src_ip,
                "src_port": int(src_port) if src_port else 0,
                "dst_ip": dst_ip,
                "dst_port": int(dst_port) if dst_port else 0,
                "action": "alert",
            }
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(
            status="unparsed",
            parser_name=self.parser_name,
            fields={},
            raw_event=raw_event,
            reason="Payload does not match Suricata EVE JSON or Snort Fast Alert syntax"
        )
