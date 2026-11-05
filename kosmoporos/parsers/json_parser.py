import json
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class JsonParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "json"

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        items: Dict[str, Any] = {}
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, new_key, sep=sep))
            else:
                items[new_key] = v
        return items

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        # Handle syslog encapsulation
        if "{" in msg and msg.endswith("}"):
            json_str = msg[msg.index("{"):]
        else:
            json_str = msg

        try:
            parsed = json.loads(json_str)
            if not isinstance(parsed, dict):
                return ParseResult(
                    status="unparsed",
                    parser_name=self.parser_name,
                    fields={},
                    raw_event=raw_event,
                    reason="Parsed JSON is not an object/dictionary"
                )
            flat_fields = self._flatten_dict(parsed)
            return ParseResult(
                status="success",
                parser_name=self.parser_name,
                fields=flat_fields,
                raw_event=raw_event
            )
        except Exception as e:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"JSON decoding failed: {str(e)}"
            )
