from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.normalization.taxonomy import (
    EventDetails,
    SourceDetails,
    DestinationDetails,
    NetworkDetails,
    DeviceDetails,
    RuleDetails,
    UserDetails,
)
from app.models.provenance import ProvenanceRecord


class UlpfMeta(BaseModel):
    schema_version: str = Field(default="1.0")
    event_id: str


class OriginalLogMeta(BaseModel):
    format: str
    message: str
    sha256: str
    transport: Optional[str] = None


class CanonicalEvent(BaseModel):
    """
    Central ULPF Intermediate Representation (ULPF-IR v1.0).
    Vendor-agnostic, SIEM-agnostic canonical representation of network logs.
    """
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
    provenance: Dict[str, ProvenanceRecord] = Field(default_factory=dict)
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="success")  # "success", "unparsed", "partial"
    reason: Optional[str] = None
