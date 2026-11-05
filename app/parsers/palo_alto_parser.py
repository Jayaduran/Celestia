import re
from typing import Dict, Any, Optional
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult
from app.parsers.c_fast_parser import c_fast_parser


class PaloAltoParser(BaseParser):
    """
    Dedicated High-Performance Parser for Palo Alto Networks PAN-OS Firewalls.
    Supports PAN-OS CSV Syslog, CEF Traffic/Threat Logs, and Key=Value formats.
    """

    @property
    def parser_name(self) -> str:
        return "palo_alto_panos"

    # Palo Alto CSV fields reference for PAN-OS v9/10/11
    PANOS_CSV_FIELDS = [
        "future_use_1", "receive_time", "serial_number", "type", "subtype",
        "future_use_2", "time_generated", "src_ip", "dst_ip", "nat_src_ip",
        "nat_dst_ip", "rule_name", "src_user", "dst_user", "app",
        "vsys", "src_zone", "dst_zone", "inbound_if", "outbound_if",
        "log_action", "future_use_3", "session_id", "repeat_count", "src_port",
        "dst_port", "nat_src_port", "nat_dst_port", "flags", "protocol",
        "action", "bytes", "bytes_sent", "bytes_received", "packets",
        "start_time", "elapsed_time", "category", "future_use_4", "seqno"
    ]

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS Next-Generation Firewall",
        }

        # 1. Check if PAN-OS CEF format
        if "CEF:" in msg and ("Palo Alto Networks" in msg or "PAN-OS" in msg or "PaloAlto" in msg):
            kv_parsed = c_fast_parser.parse_kv(msg)
            fields.update(kv_parsed)
            fields["type"] = kv_parsed.get("type", "traffic")
            fields["action"] = kv_parsed.get("act", kv_parsed.get("action", "allow"))
            fields["src_ip"] = kv_parsed.get("src", kv_parsed.get("src_ip"))
            fields["dst_ip"] = kv_parsed.get("dst", kv_parsed.get("dst_ip"))
            fields["src_port"] = kv_parsed.get("spt", kv_parsed.get("src_port"))
            fields["dst_port"] = kv_parsed.get("dpt", kv_parsed.get("dst_port"))
            fields["protocol"] = kv_parsed.get("proto", "tcp")
            fields["rule_name"] = kv_parsed.get("cs1", kv_parsed.get("rule", "default-allow"))
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        # 2. Check if PAN-OS CSV Syslog format (starts with syslog prefix or domain, followed by 1,YYYY/MM/DD... or TRAFFIC/THREAT)
        if "TRAFFIC," in msg or "THREAT," in msg or "SYSTEM," in msg or ("," in msg and len(msg.split(",")) >= 10):
            # Strip syslog header prefix if present
            csv_payload = msg
            if "," in msg:
                # Find start of Palo Alto CSV sequence (e.g., "1,202..." or "...: 1,202...")
                match = re.search(r'(?:^|:\s*)(\d+,\d{4}/\d{2}/\d{2}\s+[^,]+,[^,]+,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|CORRELATION),.+)', msg)
                if match:
                    csv_payload = match.group(1)
                elif "TRAFFIC," in msg or "THREAT," in msg:
                    parts = msg.split(",")
                    if len(parts) >= 8:
                        csv_payload = msg

            csv_parts = [p.strip() for p in csv_payload.split(",")]
            for idx, val in enumerate(csv_parts):
                if idx < len(self.PANOS_CSV_FIELDS):
                    fname = self.PANOS_CSV_FIELDS[idx]
                    if not fname.startswith("future_use"):
                        fields[fname] = val
                else:
                    fields[f"extra_field_{idx}"] = val

            # Normalize common fields
            if "type" in fields and fields["type"]:
                fields["log_type"] = fields["type"]
            
            # Ensure action is a valid normalized action token and not a timestamp or number
            known_actions = {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both", "block-url", "alert", "accept", "reject", "block"}
            act = str(fields.get("action", "")).strip().lower()
            if act not in known_actions:
                # Check if other fields hold the valid action
                if fields.get("bytes", "").lower() in known_actions:
                    fields["action"] = fields["bytes"].lower()
                elif fields.get("subtype", "").lower() in known_actions:
                    fields["action"] = fields["subtype"].lower()
                elif fields.get("log_action", "").lower() in known_actions:
                    fields["action"] = fields["log_action"].lower()
                else:
                    # Scan tokens in csv_parts for a known action token
                    matched_action = None
                    for token in csv_parts:
                        t = token.strip().lower()
                        if t in known_actions:
                            matched_action = t
                            break
                    fields["action"] = matched_action if matched_action else "allow"
            else:
                fields["action"] = act

            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        # 3. Check Key=Value format for PAN-OS
        kv_parsed = c_fast_parser.parse_kv(msg)
        if kv_parsed and ("src" in kv_parsed or "src_ip" in kv_parsed or "dst" in kv_parsed or "rule" in kv_parsed):
            fields.update(kv_parsed)
            fields["action"] = kv_parsed.get("action", kv_parsed.get("act", "allow"))
            fields["src_ip"] = kv_parsed.get("src_ip", kv_parsed.get("src"))
            fields["dst_ip"] = kv_parsed.get("dst_ip", kv_parsed.get("dst"))
            fields["src_port"] = kv_parsed.get("src_port", kv_parsed.get("spt"))
            fields["dst_port"] = kv_parsed.get("dst_port", kv_parsed.get("dpt"))
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(
            status="unparsed",
            parser_name=self.parser_name,
            fields={},
            raw_event=raw_event,
            reason="Unrecognized Palo Alto PAN-OS log syntax"
        )
