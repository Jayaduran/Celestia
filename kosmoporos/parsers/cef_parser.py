import re
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class CefParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "cef"

    CEF_START = re.compile(r"CEF:\s*(\d+)\|")

    def _parse_extension(self, extension_str: str) -> Dict[str, str]:
        ext_dict: Dict[str, str] = {}
        if not extension_str:
            return ext_dict

        pattern = re.compile(r'([a-zA-Z0-9_.-]+)=(.*?)(?=(?:\s+[a-zA-Z0-9_.-]+=|$))')
        matches = pattern.findall(extension_str)

        for key, val in matches:
            val_clean = val.strip().strip('"\'')
            ext_dict[key] = val_clean

        return ext_dict

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        start_match = self.CEF_START.search(msg)
        if not start_match:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason="CEF prefix 'CEF:<version>|' not found"
            )

        cef_body = msg[start_match.start():]
        parts = re.split(r'(?<!\\)\|', cef_body)

        if len(parts) < 7:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"CEF line has insufficient pipe separators (found {len(parts)-1}, expected >= 7)"
            )

        fields: Dict[str, Any] = {
            "cef_version": parts[0].replace("CEF:", "").strip(),
            "DeviceVendor": parts[1].replace(r"\|", "|").strip(),
            "device_vendor": parts[1].replace(r"\|", "|").strip(),
            "DeviceProduct": parts[2].replace(r"\|", "|").strip(),
            "device_product": parts[2].replace(r"\|", "|").strip(),
            "DeviceVersion": parts[3].replace(r"\|", "|").strip(),
            "device_version": parts[3].replace(r"\|", "|").strip(),
            "SignatureID": parts[4].replace(r"\|", "|").strip(),
            "signature_id": parts[4].replace(r"\|", "|").strip(),
            "Name": parts[5].replace(r"\|", "|").strip(),
            "name": parts[5].replace(r"\|", "|").strip(),
            "Severity": parts[6].replace(r"\|", "|").strip(),
            "severity": parts[6].replace(r"\|", "|").strip(),
        }

        if len(parts) >= 8:
            extension_str = "|".join(parts[7:])
            ext_fields = self._parse_extension(extension_str)
            fields.update(ext_fields)

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )
