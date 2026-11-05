import re
from typing import Dict, Any
from app.models.raw import RawEvent
from app.parsers.base import BaseParser, ParseResult


class SyslogParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "syslog"

    # Match RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    RFC5424_PATTERN = re.compile(
        r"^\s*<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
        r"(?P<appname>\S+)\s+(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s+(?P<structured_data>\[.*?\]|-)\s*(?P<msg>.*)$"
    )

    # Match RFC 3164: <PRI>MMM DD HH:MM:SS HOSTNAME APP[PID]: MSG or <PRI>MMM DD HH:MM:SS HOSTNAME MSG
    RFC3164_PATTERN = re.compile(
        r"^\s*<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>[\w\.-]+)\s+(?:(?P<appname>[\w\.-]+)(?:\[(?P<pid>\d+)\])?:?\s+)?(?P<msg>.*)$"
    )

    # Simple BSD syslog without PRI: MMM DD HH:MM:SS HOSTNAME MSG
    BSD_NO_PRI_PATTERN = re.compile(
        r"^\s*(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>[\w\.-]+)\s+(?:(?P<appname>[\w\.-]+)(?:\[(?P<pid>\d+)\])?:?\s+)?(?P<msg>.*)$"
    )

    KV_PAIR_PATTERN = re.compile(r'\b[a-zA-Z0-9_.-]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg_str = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {}

        m5424 = self.RFC5424_PATTERN.match(msg_str)
        m3164 = self.RFC3164_PATTERN.match(msg_str)
        m_bsd = self.BSD_NO_PRI_PATTERN.match(msg_str)

        if m5424:
            data = m5424.groupdict()
            pri = int(data["pri"])
            fields["pri"] = pri
            fields["facility"] = pri // 8
            fields["severity_code"] = pri % 8
            fields["syslog_version"] = data["version"]
            fields["timestamp"] = data["timestamp"]
            fields["hostname"] = data["hostname"]
            fields["appname"] = data["appname"]
            fields["procid"] = data["procid"]
            fields["msgid"] = data["msgid"]
            fields["message"] = data["msg"]
        elif m3164:
            data = m3164.groupdict()
            pri = int(data["pri"])
            fields["pri"] = pri
            fields["facility"] = pri // 8
            fields["severity_code"] = pri % 8
            fields["timestamp"] = data["timestamp"]
            fields["hostname"] = data["hostname"]
            fields["appname"] = data.get("appname")
            fields["pid"] = data.get("pid")
            fields["message"] = data["msg"]
        elif m_bsd:
            data = m_bsd.groupdict()
            fields["timestamp"] = data["timestamp"]
            fields["hostname"] = data["hostname"]
            fields["appname"] = data.get("appname")
            fields["pid"] = data.get("pid")
            fields["message"] = data["msg"]
        else:
            # Simple fallback header extraction if <PRI> exists
            pri_match = re.match(r"^\s*<(\d{1,3})>(.*)$", msg_str)
            if pri_match:
                pri = int(pri_match.group(1))
                fields["pri"] = pri
                fields["facility"] = pri // 8
                fields["severity_code"] = pri % 8
                fields["message"] = pri_match.group(2).strip()
            else:
                fields["message"] = msg_str

        # If message contains key-value pairs, parse them as sub-fields
        message_body = fields.get("message", "")
        if message_body:
            kv_matches = self.KV_PAIR_PATTERN.findall(message_body)
            for pair in kv_matches:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"\'')
                    if k not in fields:
                        fields[k] = v

            # Wi-Fi & 802.11 Wireless AP telemetry extraction
            low_msg = message_body.lower()

            # 1. MAC address detection (format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
            mac_match = re.search(r'\b([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})\b', message_body)
            if mac_match and "client_mac" not in fields and "mac" not in fields:
                fields["client_mac"] = mac_match.group(1).lower()

            # 2. Wi-Fi action detection if not already extracted
            if "action" not in fields:
                if any(k in low_msg for k in ("associated", "association", "type=association", "association request accepted", "sta associated", "wifi_connected")):
                    fields["action"] = "associated"
                    fields["event_type"] = "wifi_association"
                elif any(k in low_msg for k in ("disassociated", "disassociation", "deauthenticated", "deauth", "sta disassociated")):
                    fields["action"] = "disassociated"
                    fields["event_type"] = "wifi_disassociation"
                elif any(k in low_msg for k in ("wpa: pairwise key", "handshake completed", "user authenticated", "802.1x", "radius accept")):
                    fields["action"] = "authenticated"
                    fields["event_type"] = "wifi_auth"
                elif "roamed" in low_msg:
                    fields["action"] = "roamed"
                    fields["event_type"] = "wifi_roam"

            # 3. SSID extraction
            if "ssid" not in fields:
                ssid_match = re.search(r'(?:ssid|SSID|network)[:=\s]+([^\s,;"]+)', message_body)
                if ssid_match:
                    fields["ssid"] = ssid_match.group(1).strip('"\'')

            # 4. Signal strength / RSSI
            if "rssi" not in fields:
                rssi_match = re.search(r'(?:signal strength|rssi)[:=\s]+(-?\d+)', message_body, re.IGNORECASE)
                if rssi_match:
                    try:
                        fields["rssi"] = int(rssi_match.group(1))
                    except ValueError:
                        pass

            # 5. Wireless client IP if mentioned in body (e.g., "IP=192.168.1.145" or "assigned 192.168.1.145 to")
            if "client_ip" not in fields and "src" not in fields and "srcip" not in fields:
                ip_match = re.search(r'\b(?:ip[:=\s]+|assigned\s+)(\d{1,3}(?:\.\d{1,3}){3})\b', message_body, re.IGNORECASE)
                if ip_match:
                    fields["client_ip"] = ip_match.group(1)

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
