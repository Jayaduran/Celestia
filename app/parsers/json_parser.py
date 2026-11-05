import json
from typing import Dict, Any
from app.models.raw import RawEvent
from app.parsers.base import BaseParser, ParseResult


class JsonParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "json"

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def parse(self, raw_event: RawEvent) -> ParseResult:
        try:
            parsed_data = json.loads(raw_event.raw_message.strip())
            if not isinstance(parsed_data, dict):
                return ParseResult(
                    status="unparsed",
                    parser_name=self.parser_name,
                    fields={"raw_data": parsed_data},
                    raw_event=raw_event,
                    reason="JSON top-level content is not an object/dict"
                )

            # Flatten nested structures using dot separator, and preserve un-flattened for direct access
            flattened = self._flatten_dict(parsed_data, sep=".")
            # Combine top-level and flattened fields
            combined_fields = {**parsed_data, **flattened}

            return ParseResult(
                status="success",
                parser_name=self.parser_name,
                fields=combined_fields,
                raw_event=raw_event
            )
        except Exception as e:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"Failed to parse JSON: {str(e)}"
            )
