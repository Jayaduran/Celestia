import uuid
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, model_validator


@dataclass
class ThreatVerdict:
    """Standardized cyber threat verdict evaluated during log parsing."""
    is_threat: bool = False
    threat_type: Optional[str] = None
    severity: str = "informational"  # low, medium, high, critical, informational
    detail: Optional[str] = None
    signature: Optional[str] = None
    score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "detail": self.detail,
            "signature": self.signature,
            "score": self.score,
        }


class RawEvent(BaseModel):
    """Preserves unaltered raw log payload with cryptographic SHA-256 and chaining hash."""
    model_config = {"extra": "allow"}

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingestion_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
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
        computed_raw = hashlib.sha256(self.raw_message.encode("utf-8", errors="replace")).hexdigest()
        if not self.raw_hash or self.raw_hash != computed_raw:
            object.__setattr__(self, "raw_hash", computed_raw)
        computed_chain = hashlib.sha256((self.previous_hash + self.raw_hash).encode("utf-8")).hexdigest()
        if not self.chain_hash or self.chain_hash != computed_chain:
            object.__setattr__(self, "chain_hash", computed_chain)
        return self


class UlpfMeta(BaseModel):
    model_config = {"extra": "allow"}
    schema_version: str = Field(default="1.0")
    event_id: str


class OriginalLogMeta(BaseModel):
    model_config = {"extra": "allow"}
    format: str
    message: str
    sha256: str
    transport: Optional[str] = None


class EventDetails(BaseModel):
    model_config = {"extra": "allow"}
    id: Optional[str] = None
    category: str = "network"
    type: Optional[str] = None
    action: Optional[str] = None
    time: Optional[str] = None


class SourceDetails(BaseModel):
    model_config = {"extra": "allow"}
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None


class DestinationDetails(BaseModel):
    model_config = {"extra": "allow"}
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None


class NetworkDetails(BaseModel):
    model_config = {"extra": "allow"}
    transport: Optional[str] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    ssid: Optional[str] = None


class ProvenanceRecord(BaseModel):
    """Field-level lineage record for normalized canonical fields."""
    model_config = {"extra": "allow"}

    value: Any = None
    original_field: str = ""
    original_value: Any = None
    parser: str = "direct"
    rule: Optional[str] = "direct_mapping"
    transformation: Optional[str] = None
    evidence_type: str = "OBSERVED"
    confidence: float = 1.0
    supporting_fields: List[str] = Field(default_factory=list)


class DeviceDetails(BaseModel):
    model_config = {"extra": "allow"}
    vendor: Optional[str] = None
    product: Optional[str] = None
    hostname: Optional[str] = None
    version: Optional[str] = None


class RuleDetails(BaseModel):
    model_config = {"extra": "allow"}
    name: Optional[str] = None
    id: Optional[str] = None


class UserDetails(BaseModel):
    model_config = {"extra": "allow"}
    name: Optional[str] = None
    domain: Optional[str] = None


class CanonicalEvent(BaseModel):
    """
    Vendor-agnostic intermediate representation (ULPF-IR v1.0).
    Guarantees seamless schema validation across any framework.
    """
    model_config = {"extra": "allow"}

    ulpf: UlpfMeta
    event: EventDetails = Field(default_factory=EventDetails)
    source: SourceDetails = Field(default_factory=SourceDetails)
    destination: DestinationDetails = Field(default_factory=DestinationDetails)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    rule: RuleDetails = Field(default_factory=RuleDetails)
    user: UserDetails = Field(default_factory=UserDetails)
    severity: Optional[Any] = None
    original: OriginalLogMeta
    provenance: Dict[str, Any] = Field(default_factory=dict)
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="success")  # "success", "unparsed", "error", "blocked"
    reason: Optional[str] = None


@dataclass
class ParsedLogResult:
    """
    Standardized result emitted by KosmoporosEngine.
    """
    event_id: str
    status: str                         # success, unparsed, blocked, error
    format: str                         # detected format (CEF, Syslog, JSON, etc.)
    parser_used: str                    # identifier of parser used
    canonical_event: CanonicalEvent     # Normalized ULPF-IR event
    extracted_fields: Dict[str, Any]    # Raw key-value dictionary extracted
    threat: ThreatVerdict               # Threat analysis verdict
    raw_message: str                    # Original raw log string
    raw_sha256: str = ""                # SHA-256 hash
    latency_us: float = 0.0             # Microseconds spent parsing
    merkle_root: Optional[str] = None   # Merkle tree root hash
    merkle_block_id: Optional[int] = None # Merkle block identifier

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dict for JSON transmission across any framework."""
        return {
            "event_id": self.event_id,
            "status": self.status,
            "format": self.format,
            "parser_used": self.parser_used,
            "canonical_event": self.canonical_event.model_dump(),
            "extracted_fields": self.extracted_fields,
            "threat": self.threat.to_dict(),
            "raw_sha256": self.raw_sha256,
            "latency_us": self.latency_us,
            "merkle_root": self.merkle_root,
            "merkle_block_id": self.merkle_block_id,
        }
