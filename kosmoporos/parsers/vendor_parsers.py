import re
import json
from typing import Dict, Any, Optional
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class CiscoAsaParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "cisco_asa"

    DENY_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(106023|106015|106014):\s*Deny\s+([a-zA-Z0-9_-]+)\s+src\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)(?:/(\d+))?\s+dst\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)(?:/(\d+))?(?:\s+by\s+access-group\s+"?([^"\s]+)"?)?',
        re.IGNORECASE
    )
    BUILT_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(302013|302015|302020):\s*Built\s+(inbound|outbound)?\s*([a-zA-Z0-9_-]+)\s+connection\s+(\d+)\s+for\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)(?:\s*\([^)]*\))?\s+to\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)',
        re.IGNORECASE
    )
    TEARDOWN_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(302014|302016):\s*Teardown\s+([a-zA-Z0-9_-]+)\s+connection\s+(\d+)\s+for\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)\s+to\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)(?:.*duration\s+([\d:]+))?(?:.*bytes\s+(\d+))?',
        re.IGNORECASE
    )
    GENERIC_ASA_PATTERN = re.compile(r'%(?:ASA|FTD)-(\d)-(\d{6}):\s*(.+)')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {"vendor": "Cisco", "product": "Cisco ASA"}

        m_deny = self.DENY_PATTERN.search(msg)
        if m_deny:
            msg_code, proto, src_if, src_ip, src_port, dst_if, dst_ip, dst_port, acl = m_deny.groups()
            fields.update({
                "message_code": f"ASA-{msg_code}",
                "protocol": proto.lower(),
                "src_ip": src_ip,
                "src_port": int(src_port) if src_port else None,
                "dst_ip": dst_ip,
                "dst_port": int(dst_port) if dst_port else None,
                "action": "drop",
                "acl_rule": acl,
                "severity": "medium",
            })
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        m_built = self.BUILT_PATTERN.search(msg)
        if m_built:
            msg_code, direction, proto, conn_id, src_if, src_ip, src_port, dst_if, dst_ip, dst_port = m_built.groups()
            fields.update({
                "message_code": f"ASA-{msg_code}",
                "direction": direction.lower() if direction else "outbound",
                "protocol": proto.lower(),
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "action": "allow",
                "severity": "informational",
            })
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        m_gen = self.GENERIC_ASA_PATTERN.search(msg)
        if m_gen:
            sev, code, body = m_gen.groups()
            fields["message_code"] = f"ASA-{sev}-{code}"
            fields["message"] = body.strip()
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(status="unparsed", parser_name=self.parser_name, fields={}, raw_event=raw_event, reason="Not a recognizable Cisco ASA log")


class PaloAltoParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "palo_alto_panos"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {"vendor": "Palo Alto", "product": "PAN-OS"}

        if "," in msg:
            cols = [c.strip() for c in msg.split(",")]
            if len(cols) >= 15:
                fields.update({
                    "src_ip": cols[7] if len(cols) > 7 else None,
                    "dst_ip": cols[8] if len(cols) > 8 else None,
                    "src_port": int(cols[24]) if len(cols) > 24 and cols[24].isdigit() else None,
                    "dst_port": int(cols[25]) if len(cols) > 25 and cols[25].isdigit() else None,
                    "action": cols[29].lower() if len(cols) > 29 and cols[29] else "allow",
                    "app": cols[14] if len(cols) > 14 else None,
                })
                return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(status="unparsed", parser_name=self.parser_name, fields={}, raw_event=raw_event, reason="Not PAN-OS CSV")


class FortinetParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "fortinet_fortigate"

    KV_PATTERN = re.compile(r'([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {"vendor": "Fortinet", "product": "FortiGate"}

        matches = self.KV_PATTERN.findall(msg)
        if matches and len(matches) >= 3:
            for k, q1, q2, unq in matches:
                fields[k] = q1 or q2 or unq or ""
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(status="unparsed", parser_name=self.parser_name, fields={}, raw_event=raw_event, reason="Not FortiGate log")


class AwsCloudtrailParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "aws_cloudtrail"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        try:
            parsed = json.loads(msg)
            if isinstance(parsed, dict):
                return ParseResult(status="success", parser_name=self.parser_name, fields=parsed, raw_event=raw_event)
        except Exception:
            pass

        # VPC flow log space-delimited
        parts = msg.split()
        if len(parts) >= 14:
            fields = {
                "src_ip": parts[3],
                "dst_ip": parts[4],
                "src_port": int(parts[5]) if parts[5].isdigit() else None,
                "dst_port": int(parts[6]) if parts[6].isdigit() else None,
                "action": parts[12].lower(),
            }
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(status="unparsed", parser_name=self.parser_name, fields={}, raw_event=raw_event, reason="Not AWS log")


class SuricataParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "suricata_eve"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        try:
            parsed = json.loads(msg)
            if isinstance(parsed, dict) and "event_type" in parsed:
                return ParseResult(status="success", parser_name=self.parser_name, fields=parsed, raw_event=raw_event)
        except Exception:
            pass

        return ParseResult(status="unparsed", parser_name=self.parser_name, fields={}, raw_event=raw_event, reason="Not Suricata EVE JSON")
