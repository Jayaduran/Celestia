from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class TextParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "plain_text"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message
        return ParseResult(
            status="unparsed",
            parser_name=self.parser_name,
            fields={"raw_text": msg},
            raw_event=raw_event,
            reason="Unstructured plaintext fallback"
        )
