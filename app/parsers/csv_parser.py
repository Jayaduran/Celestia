import csv
import io
from typing import Dict, Any
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class CsvParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "csv"

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        if not msg:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="Empty CSV log message"
            )

        # Sniff delimiter (comma, tab, pipe, semicolon)
        delimiter = ","
        if "\t" in msg:
            delimiter = "\t"
        elif "|" in msg and not msg.startswith("CEF:") and not msg.startswith("LEEF:"):
            delimiter = "|"
        elif ";" in msg:
            delimiter = ";"

        try:
            reader = csv.reader(io.StringIO(msg), delimiter=delimiter)
            rows = list(reader)
            if not rows or not rows[0]:
                return ParseResult(
                    status="unparsed",
                    parser_name=self.parser_name,
                    fields={},
                    raw_event=raw_event,
                    reason="Failed to read CSV row"
                )

            row = rows[0]
            fields: Dict[str, Any] = {}
            for idx, val in enumerate(row):
                fields[f"col_{idx}"] = val.strip()

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
