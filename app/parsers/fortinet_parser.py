from typing import Dict, Any
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult
from app.parsers.c_fast_parser import c_fast_parser


class FortinetParser(BaseParser):
    """
    Dedicated Parser for Fortinet FortiGate UTM and Next-Gen Firewall Log format (FortiOS v6/7).
    Parses traffic, event, security UTM (IPS, AV, WebFilter, AppControl), and VPN logs.
    """

    @property
    def parser_name(self) -> str:
        return "fortinet_fortigate"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        # Fast C/Regex Key-Value Parsing
        kv = c_fast_parser.parse_kv(msg)
        if not kv:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="No FortiGate key-value attributes identified"
            )

        # Normalize FortiOS Fields
        fields: Dict[str, Any] = {
            "vendor": "Fortinet",
            "product": "FortiGate Next-Generation Firewall",
            "device_name": kv.get("devname", "FortiGate"),
            "device_id": kv.get("devid"),
            "log_type": kv.get("type", "traffic"),
            "subtype": kv.get("subtype", "forward"),
            "virtual_domain": kv.get("vd", "root"),
            "level": kv.get("level", "notice"),
            "src_ip": kv.get("srcip", kv.get("src")),
            "src_port": kv.get("srcport", kv.get("spt")),
            "dst_ip": kv.get("dstip", kv.get("dst")),
            "dst_port": kv.get("dstport", kv.get("dpt")),
            "protocol": kv.get("proto", "tcp"),
            "action": kv.get("action", kv.get("act", "accept")),
            "policy_id": kv.get("policyid"),
            "policy_name": kv.get("policyname"),
            "service": kv.get("service", kv.get("app")),
            "application": kv.get("app"),
            "user": kv.get("user", kv.get("unauthuser")),
            "sent_bytes": kv.get("sentbyte", kv.get("bytes_sent")),
            "received_bytes": kv.get("rcvdbyte", kv.get("bytes_received")),
            "duration": kv.get("duration"),
            "threat_name": kv.get("attack", kv.get("virus", kv.get("threat"))),
            "threat_severity": kv.get("crscore", kv.get("level")),
        }

        # Normalize Action
        act = str(fields["action"]).lower()
        if act in ("accept", "pass", "allow", "permit"):
            fields["action"] = "allow"
        elif act in ("deny", "block", "dropped", "drop", "reset", "client-rst", "server-rst"):
            fields["action"] = "deny"
        elif act in ("close", "timeout", "client-fin", "server-fin"):
            fields["action"] = "close"

        # Include all remaining raw parsed keys
        for k, v in kv.items():
            if k not in fields:
                fields[k] = v

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
