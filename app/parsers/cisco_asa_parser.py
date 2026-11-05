import re
from typing import Dict, Any, Optional
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class CiscoAsaParser(BaseParser):
    """
    Dedicated Parser for Cisco Adaptive Security Appliance (ASA), Firepower (FTD),
    and Cisco IOS Security & Access Control logs.
    """

    @property
    def parser_name(self) -> str:
        return "cisco_asa"

    # Regex patterns for high-frequency ASA messages
    # %ASA-4-106023: Deny (protocol) src [interface:]ip/port dst [interface:]ip/port by access-group "rule_name"
    DENY_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(106023|106015|106014):\s*Deny\s+([a-zA-Z0-9_-]+)\s+src\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)(?:/(\d+))?\s+dst\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)(?:/(\d+))?(?:\s+by\s+access-group\s+"?([^"\s]+)"?)?',
        re.IGNORECASE
    )

    # %ASA-6-302013 / 302015: Built (inbound|outbound) (protocol) connection (id) for [interface:]ip/port ... to [interface:]ip/port
    BUILT_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(302013|302015|302020):\s*Built\s+(inbound|outbound)?\s*([a-zA-Z0-9_-]+)\s+connection\s+(\d+)\s+for\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)(?:\s*\([^)]*\))?\s+to\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)',
        re.IGNORECASE
    )

    # %ASA-6-302014 / 302016: Teardown (protocol) connection (id) for ... duration (d) bytes (b)
    TEARDOWN_PATTERN = re.compile(
        r'%(?:ASA|FTD)-\d-(302014|302016):\s*Teardown\s+([a-zA-Z0-9_-]+)\s+connection\s+(\d+)\s+for\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)\s+to\s+(?:([a-zA-Z0-9_-]+):)?([0-9.]+)/(\d+)(?:.*duration\s+([\d:]+))?(?:.*bytes\s+(\d+))?',
        re.IGNORECASE
    )

    # Generic %ASA-X-YYYYYY message code
    GENERIC_ASA_PATTERN = re.compile(r'%(?:ASA|FTD)-(\d)-(\d{6}):\s*(.+)')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {
            "vendor": "Cisco",
            "product": "Cisco ASA / Firepower Threat Defense",
        }

        # 1. Test Deny Pattern
        m_deny = self.DENY_PATTERN.search(msg)
        if m_deny:
            msg_code, proto, src_if, src_ip, src_port, dst_if, dst_ip, dst_port, acl = m_deny.groups()
            fields.update({
                "cisco_message_code": f"%ASA-{msg_code}",
                "action": "deny",
                "protocol": proto.lower(),
                "src_interface": src_if or "unknown",
                "src_ip": src_ip,
                "src_port": int(src_port) if src_port else 0,
                "dst_interface": dst_if or "unknown",
                "dst_ip": dst_ip,
                "dst_port": int(dst_port) if dst_port else 0,
                "rule_name": acl or "default_deny",
                "severity": "medium" if msg_code == "106023" else "high",
            })
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        # 2. Test Built Connection Pattern
        m_built = self.BUILT_PATTERN.search(msg)
        if m_built:
            msg_code, direction, proto, conn_id, src_if, src_ip, src_port, dst_if, dst_ip, dst_port = m_built.groups()
            fields.update({
                "cisco_message_code": f"%ASA-{msg_code}",
                "action": "allow",
                "direction": direction.lower() if direction else "inbound",
                "protocol": proto.lower(),
                "connection_id": conn_id,
                "src_interface": src_if or "outside",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_interface": dst_if or "inside",
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "severity": "informational",
            })
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        # 3. Test Teardown Connection Pattern
        m_tear = self.TEARDOWN_PATTERN.search(msg)
        if m_tear:
            msg_code, proto, conn_id, src_if, src_ip, src_port, dst_if, dst_ip, dst_port, duration, bytes_cnt = m_tear.groups()
            fields.update({
                "cisco_message_code": f"%ASA-{msg_code}",
                "action": "close",
                "protocol": proto.lower(),
                "connection_id": conn_id,
                "src_interface": src_if or "outside",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_interface": dst_if or "inside",
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "duration": duration or "0:00:00",
                "bytes": int(bytes_cnt) if bytes_cnt else 0,
                "severity": "informational",
            })
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        # 4. Generic %ASA fallback
        m_gen = self.GENERIC_ASA_PATTERN.search(msg)
        if m_gen:
            sev_num, code, text = m_gen.groups()
            fields.update({
                "cisco_message_code": f"%ASA-{code}",
                "severity_code": int(sev_num),
                "message_text": text.strip(),
                "action": "alert" if int(sev_num) <= 4 else "informational",
            })
            # Try to extract IPs and ports if present
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
            if len(ip_matches) >= 2:
                fields["src_ip"] = ip_matches[0]
                fields["dst_ip"] = ip_matches[1]
            elif len(ip_matches) == 1:
                fields["src_ip"] = ip_matches[0]

            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(
            status="unparsed",
            parser_name=self.parser_name,
            fields={},
            raw_event=raw_event,
            reason="No Cisco ASA message pattern matched"
        )
