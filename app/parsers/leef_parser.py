import re
from typing import Dict, Any
from app.models.raw import RawEvent
from app.parsers.base import BaseParser, ParseResult


class LeefParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "leef"

    LEEF_START = re.compile(r"LEEF:\s*(\d+(?:\.\d+)?)\|")

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        start_match = self.LEEF_START.search(msg)
        if not start_match:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="LEEF prefix 'LEEF:<version>|' not found"
            )

        leef_body = msg[start_match.start():]
        parts = re.split(r'(?<!\\)\|', leef_body)

        if len(parts) < 5:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"LEEF line has insufficient pipe separators (found {len(parts)-1}, expected >= 5)"
            )

        # Version header, Vendor, Product, Version, EventID
        leef_version = parts[0].split(":", 1)[1] if ":" in parts[0] else "1.0"

        fields: Dict[str, Any] = {
            "LEEF_Version": leef_version.strip(),
            "Vendor": parts[1].strip(),
            "Product": parts[2].strip(),
            "Version": parts[3].strip(),
            "EventID": parts[4].strip(),
        }

        # Check for optional custom delimiter or extension
        remaining = parts[5:] if len(parts) > 5 else []
        if remaining:
            extension_str = "|".join(remaining)
            
            # Determine delimiter (default tab or caret or space if specified)
            delimiter = "\t"
            if len(remaining) >= 2 and len(remaining[0]) == 1 and not remaining[0].isalnum():
                delimiter = remaining[0]
                extension_str = "|".join(remaining[1:])

            # Parse extensions using delimiter or regex
            kv_pairs = re.split(r'[' + re.escape(delimiter) + r'\t]+', extension_str)
            for item in kv_pairs:
                if "=" in item:
                    k, v = item.split("=", 1)
                    fields[k.strip()] = v.strip().strip('"\'')

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
