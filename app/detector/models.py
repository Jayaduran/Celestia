from pydantic import BaseModel


class DetectionResult(BaseModel):
    format: str  # JSON, Syslog, CEF, LEEF, Key=Value, CSV, XML, Plaintext
    confidence: float
    reason: str
