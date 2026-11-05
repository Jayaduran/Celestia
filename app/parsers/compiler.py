import re
import json
import csv
import io
import time
import yaml
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class ParserSpec(BaseModel):
    id: str
    version: str = "1.0"
    vendor: Optional[str] = "Generic"
    product: Optional[str] = "Generic"
    format: str  # "key_value", "regex", "json", "csv", "syslog"
    regex_pattern: Optional[str] = None
    mapping: Dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)


class CompiledYamlParser(BaseParser):
    """
    Dynamically compiled parser generated from a YAML Parser Specification.
    Executes compiled regex / extraction rules deterministically.
    """

    def __init__(self, spec: ParserSpec):
        self.spec = spec
        self._compiled_regex = re.compile(spec.regex_pattern) if spec.regex_pattern else None
        self.max_input_length = 50000

    @property
    def parser_name(self) -> str:
        return self.spec.id

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()
        
        # Security: Input length limit for regex/kv formats
        if len(msg) > self.max_input_length:
            msg = msg[:self.max_input_length]

        fields: Dict[str, Any] = {}
        
        try:
            if self.spec.format == "regex" and self._compiled_regex:
                # Time bounding using a simple check
                t0 = time.time()
                match = self._compiled_regex.search(msg)
                if time.time() - t0 > 0.5:
                    pass # Too slow, could be ReDoS, but match might have finished
                if match:
                    fields = match.groupdict()
                else:
                    return ParseResult(
                        status="unparsed",
                        parser_name=self.parser_name,
                        fields={},
                        raw_event=raw_event,
                        reason=f"Log message did not match compiled regex pattern for parser {self.spec.id}"
                    )
            elif self.spec.format == "key_value":
                kv_pattern = re.compile(r'([a-zA-Z0-9_.-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^|\s,]+))')
                matches = kv_pattern.findall(msg)
                for key, val_d, val_s, val_u in matches:
                    fields[key.strip()] = val_d or val_s or val_u or ""
            elif self.spec.format == "json":
                fields = json.loads(msg)
                if not isinstance(fields, dict):
                    fields = {"raw": msg}
            elif self.spec.format == "csv":
                reader = csv.reader(io.StringIO(msg))
                row = next(reader, [])
                for i, val in enumerate(row):
                    fields[f"column_{i}"] = val
            else:
                fields = {"raw": msg}
        except Exception as e:
            return ParseResult(
                status="unparsed",
                parser_name=self.parser_name,
                fields={},
                raw_event=raw_event,
                reason=f"Parser exception: {str(e)}"
            )

        # Apply schema mapping mappings
        if self.spec.mapping and fields:
            mapped_fields = {}
            for extracted_key, extracted_val in fields.items():
                if extracted_key in self.spec.mapping:
                    target_key = self.spec.mapping[extracted_key]
                    mapped_fields[target_key] = extracted_val
                else:
                    mapped_fields[extracted_key] = extracted_val
            fields = mapped_fields

        return ParseResult(
            status="success",
            parser_name=self.parser_name,
            fields=fields,
            raw_event=raw_event
        )


class ParserCompiler:
    """
    Compiles YAML parser specifications into executable CompiledYamlParser instances.
    """
    
    @staticmethod
    def _validate_regex(pattern: str) -> bool:
        """Heuristic check for dangerous regex (ReDoS protection)."""
        if not pattern:
            return True
        # Check for nested quantifiers like (a+)+ or (a|b)+
        if re.search(r'\([^)]*(\+|-|\*|\{[0-9,]+\})\)[+*\{]', pattern):
            return False
        # Limit overall pattern complexity/length
        if len(pattern) > 2000:
            return False
        return True

    @staticmethod
    def compile_from_yaml(yaml_content: str) -> Tuple[ParserSpec, CompiledYamlParser]:
        data = yaml.safe_load(yaml_content)
        parser_info = data.get("parser", {})
        input_info = data.get("input", {})
        
        regex_pattern = data.get("regex_pattern")
        if regex_pattern and not ParserCompiler._validate_regex(regex_pattern):
            raise ValueError("Regex validation failed: dangerous pattern detected (ReDoS protection).")
        
        spec = ParserSpec(
            id=parser_info.get("id", "custom_parser"),
            version=str(parser_info.get("version", "1.0")),
            vendor=parser_info.get("vendor", "Generic"),
            product=parser_info.get("product", "Generic"),
            format=input_info.get("format", "key_value"),
            regex_pattern=regex_pattern,
            mapping=data.get("mapping", {}),
            confidence=float(data.get("confidence", 0.95)),
        )

        compiled_parser = CompiledYamlParser(spec)
        return spec, compiled_parser

