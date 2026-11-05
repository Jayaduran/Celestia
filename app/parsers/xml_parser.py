import xml.etree.ElementTree as ET
from typing import Dict, Any
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class XmlParser(BaseParser):
    @property
    def parser_name(self) -> str:
        return "xml"

    def _element_to_dict(self, elem: ET.Element, parent_prefix: str = "") -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        current_prefix = f"{parent_prefix}.{tag_name}" if parent_prefix else tag_name

        # Attributes
        for k, v in elem.attrib.items():
            fields[f"{current_prefix}.@{k}"] = v

        # Text content
        if elem.text and elem.text.strip():
            fields[current_prefix] = elem.text.strip()

        # Children
        for child in elem:
            child_fields = self._element_to_dict(child, current_prefix)
            fields.update(child_fields)

        return fields

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        try:
            root = ET.fromstring(msg)
            extracted = self._element_to_dict(root)
            return ParseResult(
                status="success",
                parser_name=self.parser_name,
                fields=extracted,
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
