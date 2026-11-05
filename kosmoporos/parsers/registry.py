from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from kosmoporos.parsers.base import BaseParser
from kosmoporos.parsers.syslog_parser import SyslogParser
from kosmoporos.parsers.json_parser import JsonParser
from kosmoporos.parsers.cef_parser import CefParser
from kosmoporos.parsers.leef_parser import LeefParser
from kosmoporos.parsers.kv_parser import KvParser
from kosmoporos.parsers.csv_parser import CsvParser
from kosmoporos.parsers.xml_parser import XmlParser
from kosmoporos.parsers.text_parser import TextParser
from kosmoporos.parsers.vendor_parsers import (
    CiscoAsaParser,
    PaloAltoParser,
    FortinetParser,
    AwsCloudtrailParser,
    SuricataParser,
)


class ParserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"
    DEPRECATED = "DEPRECATED"


@dataclass
class ParserMetadata:
    id: str
    name: Optional[str] = None
    vendor: str = "Generic"
    product: str = "Generic"
    format: str = "Generic"
    version: str = "1.0"
    confidence: float = 1.0
    status: ParserStatus = ParserStatus.ACTIVE


class ParserRegistry:
    """Central registry of deterministic log parsers for Kosmoporos."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._metadata: Dict[str, ParserMetadata] = {}
        self._register_builtins()

    def _register_builtins(self):
        builtins = [
            ("syslog", SyslogParser(), "Generic", "Syslog", "Syslog", "Universal Syslog Parser"),
            ("json", JsonParser(), "Generic", "JSON Stream", "JSON", "Universal JSON Parser"),
            ("cef", CefParser(), "Multi-Vendor", "CEF Device", "CEF", "Common Event Format Parser"),
            ("leef", LeefParser(), "IBM", "QRadar", "LEEF", "Log Event Extended Format Parser"),
            ("key_value", KvParser(), "Generic", "Firewall", "Key=Value", "Key=Value Pair Parser"),
            ("csv", CsvParser(), "Generic", "CSV", "CSV", "Delimited CSV Parser"),
            ("xml", XmlParser(), "Generic", "XML", "XML", "Universal XML Parser"),
            ("plain_text", TextParser(), "Generic", "Plaintext", "Plaintext", "Raw Plaintext Fallback"),
            ("palo_alto_panos", PaloAltoParser(), "Palo Alto Networks", "PAN-OS", "CSV / CEF / KV", "Palo Alto Parser"),
            ("cisco_asa", CiscoAsaParser(), "Cisco", "ASA / FTD", "Syslog", "Cisco ASA Parser"),
            ("fortinet_fortigate", FortinetParser(), "Fortinet", "FortiGate", "Key=Value", "Fortinet FortiGate Parser"),
            ("aws_cloudtrail", AwsCloudtrailParser(), "Amazon Web Services", "CloudTrail", "JSON / Flow", "AWS CloudTrail Parser"),
            ("suricata_eve", SuricataParser(), "OISF", "Suricata EVE", "JSON / Alert", "Suricata EVE Parser"),
        ]

        for pid, instance, vendor, product, fmt, custom_name in builtins:
            self._parsers[pid] = instance
            self._metadata[pid] = ParserMetadata(
                id=pid,
                name=custom_name,
                vendor=vendor,
                product=product,
                format=fmt,
                version="1.0",
                confidence=1.0,
                status=ParserStatus.ACTIVE,
            )

    def get_parser(self, parser_id: str) -> Optional[BaseParser]:
        return self._parsers.get(parser_id)

    def get_metadata(self, parser_id: str) -> Optional[ParserMetadata]:
        return self._metadata.get(parser_id)

    def register_parser(self, parser: BaseParser, metadata: ParserMetadata):
        self._parsers[parser.parser_name] = parser
        self._metadata[parser.parser_name] = metadata

    def list_parsers(self) -> List[ParserMetadata]:
        return list(self._metadata.values())
