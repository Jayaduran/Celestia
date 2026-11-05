import re
from typing import Dict, Any
from app.models.raw import RawEvent
from app.parsers.base import BaseParser, ParseResult


class KvParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "key_value"

    # Regex matches key=value where value can be quoted ("...", '...') or unquoted single token
    KV_PATTERN = re.compile(r'([a-zA-Z0-9_.-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))')

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        matches = self.KV_PATTERN.findall(msg)
        if not matches:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="No Key=Value pairs could be extracted from log message"
            )

        fields: Dict[str, Any] = {}
        for key, val_double, val_single, val_unquoted in matches:
            val = val_double or val_single or val_unquoted or ""
            fields[key.strip()] = val.strip()

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
