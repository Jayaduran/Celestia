import json
import re
import xml.etree.ElementTree as ET
from app.detector.models import DetectionResult


class FormatDetector:
    """
    Deterministic Format & Vendor Detector for ULPF.
    Identifies standard formats (CEF, LEEF, Syslog, JSON, XML, KV, CSV)
    and specialized enterprise vendor signatures (Palo Alto, Cisco ASA, Fortinet, AWS, Suricata).
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
            return DetectionResult(
                format="Cisco ASA (Syslog)",
                confidence=0.99,
                reason="Cisco ASA/FTD security message code detected"
            )

        if self.SNORT_FAST_PATTERN.search(msg):
            return DetectionResult(
                format="Suricata / Snort (Syslog)",
                confidence=0.98,
                reason="Snort/Suricata Fast Alert syntax detected"
            )

        if self.PANOS_CSV_PATTERN.search(msg) or ("PaloAlto" in msg and "CEF:" in msg) or ("TRAFFIC," in msg and len(msg.split(",")) >= 10):
            return DetectionResult(
                format="Palo Alto PAN-OS (Syslog)",
                confidence=0.98,
                reason="Palo Alto Networks PAN-OS log pattern detected"
            )

        if self.AWS_VPC_PATTERN.search(msg):
            return DetectionResult(
                format="AWS CloudTrail / VPC Flow (Plaintext)",
                confidence=0.98,
                reason="AWS VPC Flow log v2 schema detected"
            )

        if self.FORTINET_PATTERN.search(msg) and ("srcip=" in msg or "devid=" in msg or 'vd="root"' in msg or "policyid=" in msg):
            return DetectionResult(
                format="Fortinet FortiGate (Key=Value)",
                confidence=0.98,
                reason="Fortinet FortiOS key-value UTM pattern detected"
            )

        # 1. CEF
        if self.CEF_PATTERN.search(msg):
            return DetectionResult(
                format="CEF",
                confidence=0.99,
                reason="CEF header pattern detected"
            )

        # 2. LEEF
        if self.LEEF_PATTERN.search(msg):
            return DetectionResult(
                format="LEEF",
                confidence=0.99,
                reason="LEEF header pattern detected"
            )

        # 3. JSON (Check for AWS CloudTrail / Suricata EVE inside JSON)
        if (msg.startswith("{") and msg.endswith("}")) or (msg.startswith("[") and msg.endswith("]")):
            try:
                parsed_json = json.loads(msg)
                if isinstance(parsed_json, dict):
                    if "eventSource" in parsed_json and "eventName" in parsed_json:
                        return DetectionResult(
                            format="AWS CloudTrail / VPC Flow (JSON)",
                            confidence=0.99,
                            reason="AWS CloudTrail JSON schema detected"
                        )
                    if "event_type" in parsed_json and ("alert" in parsed_json or "flow" in parsed_json):
                        return DetectionResult(
                            format="Suricata / Snort (JSON)",
                            confidence=0.99,
                            reason="Suricata EVE JSON alert telemetry detected"
                        )
                return DetectionResult(
                    format="JSON",
                    confidence=1.0,
                    reason="Valid JSON structure parsed successfully"
                )
            except Exception:
                pass

        # 4. XML
        if msg.startswith("<") and msg.endswith(">") and not msg.startswith("<PRI>"):
            try:
                ET.fromstring(msg)
                return DetectionResult(
                    format="XML",
                    confidence=0.98,
                    reason="Valid XML structure parsed successfully"
                )
            except Exception:
                pass

        # 5. Syslog
        if self.SYSLOG_PRI_PATTERN.search(msg):
            return DetectionResult(
                format="Syslog",
                confidence=0.95,
                reason="Syslog PRI (<facility.severity>) header detected"
            )
        if self.SYSLOG_BSD_PATTERN.search(msg):
            return DetectionResult(
                format="Syslog",
                confidence=0.90,
                reason="Syslog BSD RFC 3164 timestamp/hostname header detected"
            )

        # 5.5 Proprietary / Industrial Unknown Telemetry Detection
        proprietary_markers = (
            "[SCADA", "SCADA-", "[MODBUS", "PLC-", "[PLC", "SENSOR-STREAM",
            "CUSTOM_PROXY", "DEV=RTU-", "DEV=SCADA-", "DEV=IoT-", "[SCADA_V2]"
        )
        if any(marker.lower() in msg.lower() for marker in proprietary_markers) or ("|" in msg and not msg.startswith("CEF:") and not msg.startswith("LEEF:")):
            return DetectionResult(
                format="Unknown (Proprietary)",
                confidence=0.85,
                reason="Proprietary industrial/custom telemetry syntax detected requiring AI inference"
            )

        # 6. Key=Value (Standard known space-separated pairs)
        kv_matches = self.KV_PAIR_PATTERN.findall(msg)
        if len(kv_matches) >= 2:
            return DetectionResult(
                format="Key=Value",
                confidence=min(0.70 + (len(kv_matches) * 0.05), 0.95),
                reason=f"Detected {len(kv_matches)} Key=Value pair patterns"
            )

        # 7. CSV check (comma separated with >= 3 columns)
        if "," in msg and len(msg.split(",")) >= 3:
            return DetectionResult(
                format="CSV",
                confidence=0.75,
                reason="Delimited CSV column structure detected"
            )

        # 8. Fallback to Plaintext / Unknown
        return DetectionResult(
            format="Plaintext",
            confidence=0.20,
            reason="Unrecognized format; treated as plain text log"
        )
