import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class RawIngress(BaseModel):
    """
    Common Raw Ingress Data Object.
    Unified representation of raw data arriving from any transport connector
    (UDP Syslog, TCP Syslog, REST API, File Tail, or Kafka/Redpanda).
    """
    event_id: Optional[str] = None
    connector_type: str = Field(..., description="Transport connector identifier: syslog_udp, syslog_tcp, rest, file_tail, redpanda")
    source: str = Field(..., description="Source device identifier, client IP, or file path")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_text: str = Field(..., description="Verbatim raw log string (unmodified)")
    raw_sha256: str = Field(default="")
    transport_metadata: Dict[str, Any] = Field(default_factory=dict)
    vendor_hint: Optional[str] = None
    product_hint: Optional[str] = None
    format_hint: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        """Compute UUID and SHA-256 hash immediately upon ingress if not already provided."""
        import uuid
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.raw_sha256 and self.raw_text is not None:
            self.raw_sha256 = hashlib.sha256(self.raw_text.encode("utf-8")).hexdigest()

    @property
    def raw_log(self) -> str:
        return self.raw_text

    @property
    def transport(self) -> str:
        return self.connector_type

    @property
    def source_ip(self) -> str:
        return self.source
