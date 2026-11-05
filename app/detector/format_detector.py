import json
import re
from pydantic import BaseModel


class DetectionResult(BaseModel):
    format: str
    confidence: float
    reason: str


class FormatDetector:
    """
    Deterministic Format Detector for ULPF.
    Analyzes log structure without relying on external ML models or LLMs.
    """

    # Common CEF Header Pattern: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
    CEF_PATTERN = re.compile(r"^\s*(?:<\d+>)?(?:\w{3}\s+\d+\s+\d+:\d+:\d+\s+[\w\.-]+\s+)?CEF:\s*\d+\|", re.IGNORECASE)

    # Common LEEF Header Pattern: LEEF:Version|Vendor|Product|Version|EventID| or LEEF:1.0| or LEEF:2.0|
    LEEF_PATTERN = re.compile(r"^\s*(?:<\d+>)?(?:\w{3}\s+\d+\s+\d+:\d+:\d+\s+[\w\.-]+\s+)?LEEF:\s*\d+(?:\.\d+)?\|", re.IGNORECASE)

    # Syslog PRI header pattern <0-191> followed by RFC3164/5424 date/timestamp
    SYSLOG_PRI_PATTERN = re.compile(r"^\s*<(\d{1,3})>(?:1\s+)?(?:\d{4}-\d{2}-\d{2}T|\w{3}\s+\d+\s+\d+:\d+:\d+)?")
    SYSLOG_BSD_PATTERN = re.compile(r"^\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\w\.-]+")

    # Key=Value pattern: matches src=10.0.0.1 or dst="8.8.8.8" or proto=tcp
    KV_PAIR_PATTERN = re.compile(r'\b[a-zA-Z0-9_.-]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)')

    def detect(self, raw_message: str) -> DetectionResult:
        if not raw_message or not raw_message.strip():
            return DetectionResult(
                format="Plaintext",
                confidence=0.0,
                reason="Empty or whitespace-only log message"
            )

        msg = raw_message.strip()

        # 1. Check CEF
        if self.CEF_PATTERN.search(msg):
            return DetectionResult(
                format="CEF",
                confidence=0.99,
                reason="CEF header pattern detected"
            )

        # 2. Check LEEF
        if self.LEEF_PATTERN.search(msg):
            return DetectionResult(
                format="LEEF",
                confidence=0.99,
                reason="LEEF header pattern detected"
            )

        # 3. Check JSON
        if (msg.startswith("{") and msg.endswith("}")) or (msg.startswith("[") and msg.endswith("]")):
            try:
                json.loads(msg)
                return DetectionResult(
                    format="JSON",
                    confidence=1.0,
                    reason="Valid JSON structure parsed successfully"
                )
            except Exception:
                pass

        # 4. Check Syslog
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

        # 5. Check Key=Value
        kv_matches = self.KV_PAIR_PATTERN.findall(msg)
        if len(kv_matches) >= 2:
            return DetectionResult(
                format="Key=Value",
                confidence=min(0.70 + (len(kv_matches) * 0.05), 0.95),
                reason=f"Detected {len(kv_matches)} Key=Value pair patterns"
            )

        # 6. Fallback to Plaintext / Unknown
        return DetectionResult(
            format="Plaintext",
            confidence=0.20,
            reason="Unrecognized format; treated as plain text log"
        )
