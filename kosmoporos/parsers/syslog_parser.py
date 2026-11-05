import re
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class SyslogParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "syslog"

    RFC5424_PATTERN = re.compile(
        r"^\s*<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
        r"(?P<appname>\S+)\s+(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s+(?P<structured_data>\[.*?\]|-)\s*(?P<msg>.*)$"
    )

    RFC3164_PATTERN = re.compile(
        r"^\s*<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>[\w\.-]+)\s+(?:(?P<appname>[\w\.-]+)(?:\[(?P<pid>\d+)\])?:?\s+)?(?P<msg>.*)$"
    )

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
            fields["procid"] = data.get("pid")
            fields["message"] = data["msg"]
        elif m_bsd:
            data = m_bsd.groupdict()
            fields["timestamp"] = data["timestamp"]
            fields["hostname"] = data["hostname"]
            fields["appname"] = data.get("appname")
            fields["procid"] = data.get("pid")
            fields["message"] = data["msg"]
        else:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="Does not conform to RFC 5424 or RFC 3164 Syslog format"
            )

        payload_msg = fields.get("message", "")
        if payload_msg:
            for kv in self.KV_PAIR_PATTERN.findall(payload_msg):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    fields[k.strip()] = v.strip().strip('"\'')

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
