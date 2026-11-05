import xml.etree.ElementTree as ET
from typing import Dict, Any
from kosmoporos.models import RawEvent
from kosmoporos.parsers.base import BaseParser, ParseResult


class XmlParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "xml"

    def _elem_to_dict(self, elem: ET.Element) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for k, v in elem.attrib.items():
            d[f"@{k}"] = v
        if elem.text and elem.text.strip():
            d["#text"] = elem.text.strip()
        for child in elem:
            child_data = self._elem_to_dict(child)
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if tag in d:
                if isinstance(d[tag], list):
                    d[tag].append(child_data)
                else:
                    d[tag] = [d[tag], child_data]
            else:
                d[tag] = child_data
        return d

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        try:
            root = ET.fromstring(msg)
            fields = self._elem_to_dict(root)
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
                reason=f"XML parse error: {str(e)}"
            )
