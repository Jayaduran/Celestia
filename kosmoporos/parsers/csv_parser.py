import csv
import io
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class CsvParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "csv"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        try:
            reader = csv.reader(io.StringIO(msg))
            row = next(reader, None)
            if not row or len(row) < 3:
                return ParseResult(
                    status="unparsed",
                    parser_name=self.parser_name,
                    fields={},
                    raw_event=raw_event,
                    reason="CSV row has fewer than 3 columns"
                )
            fields: Dict[str, Any] = {f"col_{i}": val.strip() for i, val in enumerate(row)}
            return ParseResult(
                status="success",
                parser_name=self.parser_name,
                fields=fields,
                raw_event=raw_event
            )
        except Exception as e:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"CSV parse error: {str(e)}"
            )
