import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    format: str
    confidence: float
    reason: Optional[str] = None


class FormatDetector:
    """
    Deterministic Format & Vendor Detector for Kosmoporos.
    Zero external dependencies.
    """

    CEF_PATTERN = re.compile(r"^\s*(?:<\d+>)?(?:\w{3}\s+\d+\s+\d+:\d+:\d+\s+[\w\.-]+\s+)?CEF:\s*\d+\|", re.IGNORECASE)
    LEEF_PATTERN = re.compile(r"^\s*(?:<\d+>)?(?:\w{3}\s+\d+\s+\d+:\d+:\d+\s+[\w\.-]+\s+)?LEEF:\s*\d+(?:\.\d+)?\|", re.IGNORECASE)
    SYSLOG_PRI_PATTERN = re.compile(r"^\s*<(\d{1,3})>(?:1\s+)?(?:\d{4}-\d{2}-\d{2}T|\w{3}\s+\d+\s+\d+:\d+:\d+)?")
    SYSLOG_BSD_PATTERN = re.compile(r"^\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\w\.-]+")
    KV_PAIR_PATTERN = re.compile(r'\b[a-zA-Z0-9_.-]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)')

    # Specific Vendor Signatures
    CISCO_ASA_PATTERN = re.compile(r'%(?:ASA|FTD)-\d-\d{6}:')
    FORTINET_PATTERN = re.compile(r'(?:devname=|type="?(?:traffic|utm|event)"?|subtype="?(?:forward|system|virus|ips|webfilter)"?)', re.IGNORECASE)
    PANOS_CSV_PATTERN = re.compile(r'(?:^|:\s*)\d+,\d{4}/\d{2}/\d{2}\s+[^,]+,[^,]+,(?:TRAFFIC|THREAT|SYSTEM|CONFIG),')
    AWS_VPC_PATTERN = re.compile(r'^\s*\d+\s+\d{12}\s+eni-[0-9a-fA-F]+\s+')
    SNORT_FAST_PATTERN = re.compile(r'\[\*\*\]\s*\[\d+:\d+:\d+\]\s*[^\[]+\s*\[\*\*\]')

    def detect(self, raw_message: str) -> DetectionResult:
        if not raw_message or not raw_message.strip():
            return DetectionResult(
                format="Plaintext",
                confidence=0.0,
                reason="Empty or whitespace-only log message"
            )

        msg = raw_message.strip()

        # 0. Specialized Vendor Signatures (High Precision)
        if self.CISCO_ASA_PATTERN.search(msg):
            return DetectionResult(format="Cisco ASA (Syslog)", confidence=0.99, reason="Cisco ASA/FTD security message code detected")

        if self.SNORT_FAST_PATTERN.search(msg):
            return DetectionResult(format="Suricata / Snort (Syslog)", confidence=0.98, reason="Snort/Suricata Fast Alert syntax detected")

        if self.PANOS_CSV_PATTERN.search(msg) or ("TRAFFIC," in msg and len(msg.split(",")) >= 10):
            return DetectionResult(format="Palo Alto PAN-OS (Syslog)", confidence=0.98, reason="Palo Alto Networks PAN-OS log pattern detected")

        if self.AWS_VPC_PATTERN.search(msg):
            return DetectionResult(format="AWS CloudTrail / VPC Flow (Plaintext)", confidence=0.95, reason="AWS VPC Flow log space-delimited syntax detected")

        if self.FORTINET_PATTERN.search(msg):
            return DetectionResult(format="Fortinet FortiGate (Key=Value)", confidence=0.95, reason="Fortinet FortiGate UTM log attributes detected")

        # 1. CEF Standard
        if self.CEF_PATTERN.search(msg):
            return DetectionResult(format="CEF", confidence=0.99, reason="Common Event Format (CEF) header detected")

        # 2. LEEF Standard
        if self.LEEF_PATTERN.search(msg):
            return DetectionResult(format="LEEF", confidence=0.99, reason="Log Event Extended Format (LEEF) header detected")

        # 3. JSON Structure
        if (msg.startswith("{") and msg.endswith("}")) or (msg.startswith("[") and msg.endswith("]")):
            try:
                parsed = json.loads(msg)
                if isinstance(parsed, dict):
                    if "eventVersion" in parsed and "eventSource" in parsed:
                        return DetectionResult(format="AWS CloudTrail / VPC Flow", confidence=0.99, reason="AWS CloudTrail JSON event structure detected")
                    if "event_type" in parsed and ("flow_id" in parsed or "alert" in parsed):
                        return DetectionResult(format="Suricata / Snort", confidence=0.99, reason="Suricata EVE JSON event structure detected")
                    return DetectionResult(format="JSON", confidence=1.0, reason="Valid structured JSON document")
            except (json.JSONDecodeError, ValueError):
                pass

        # 4. Syslog Standard (RFC 5424 / RFC 3164)
        if self.SYSLOG_PRI_PATTERN.search(msg) or self.SYSLOG_BSD_PATTERN.search(msg):
            if "{" in msg and msg.endswith("}"):
                try:
                    json_part = msg[msg.index("{"):]
                    json.loads(json_part)
                    return DetectionResult(format="JSON", confidence=0.95, reason="Syslog-encapsulated JSON payload")
                except Exception:
                    pass

            kv_matches = self.KV_PAIR_PATTERN.findall(msg)
            if len(kv_matches) >= 3:
                return DetectionResult(format="Key=Value", confidence=0.90, reason="Syslog-wrapped Key=Value structured payload")

            return DetectionResult(format="Syslog", confidence=0.95, reason="Standard Syslog RFC 3164/5424 header structure")

        # 5. XML Structure
        if msg.startswith("<") and msg.endswith(">") and not msg.startswith("<script"):
            try:
                ET.fromstring(msg)
                return DetectionResult(format="XML", confidence=0.95, reason="Valid structured XML document")
            except Exception:
                pass

        # 6. Key=Value Pairs
        kv_matches = self.KV_PAIR_PATTERN.findall(msg)
        if len(kv_matches) >= 3:
            return DetectionResult(format="Key=Value", confidence=0.85, reason=f"Extracted {len(kv_matches)} distinct key=value token pairs")

        # 7. CSV / Delimited
        if "," in msg:
            parts = [p.strip() for p in msg.split(",")]
            if len(parts) >= 5 and all(len(p) > 0 for p in parts[:4]):
                return DetectionResult(format="CSV", confidence=0.75, reason=f"Comma-delimited sequence with {len(parts)} columns")

        # 8. Unstructured Fallback
        return DetectionResult(format="Plaintext", confidence=0.50, reason="Unstructured freeform text")
