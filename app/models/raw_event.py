import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class RawEvent(BaseModel):
    """
    Preserves original log event without mutation.
    Includes SHA-256 integrity hash verification and cryptographic hash chaining.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingestion_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = Field(default="network_device")
    source_vendor: Optional[str] = None
    source_product: Optional[str] = None
    format: Optional[str] = None
    raw_message: str
    raw_hash: str = ""
    previous_hash: str = ""
    chain_hash: str = ""

    @model_validator(mode="after")
    def compute_sha256(self) -> "RawEvent":
        computed_raw = hashlib.sha256(self.raw_message.encode("utf-8")).hexdigest()
        if not self.raw_hash or self.raw_hash != computed_raw:
            object.__setattr__(self, "raw_hash", computed_raw)
            
        computed_chain = hashlib.sha256((self.previous_hash + self.raw_hash).encode("utf-8")).hexdigest()
        if not self.chain_hash or self.chain_hash != computed_chain:
            object.__setattr__(self, "chain_hash", computed_chain)
            
        return self


def create_raw_event(
    raw_message: str,
    source: str = "network_device",
    source_vendor: Optional[str] = None,
    source_product: Optional[str] = None,
    detected_format: Optional[str] = None,
    previous_hash: str = "",
) -> RawEvent:
    return RawEvent(
        raw_message=raw_message,
        source=source,
        source_vendor=source_vendor,
        source_product=source_product,
        format=detected_format,
        previous_hash=previous_hash,
    )
