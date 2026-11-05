import re
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class KvParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "key_value"

    KV_PATTERN = re.compile(r'([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        fields: Dict[str, Any] = {}

        matches = self.KV_PATTERN.findall(msg)
        if not matches or len(matches) < 2:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="Fewer than 2 key=value pairs found in message"
            )

        for match in matches:
            key = match[0]
            val = match[1] or match[2] or match[3] or ""
            fields[key] = val

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
