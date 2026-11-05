from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.models.taxonomy import (
    EventDetails,
    SourceDetails,
    DestinationDetails,
    NetworkDetails,
    DeviceDetails,
    RuleDetails,
    UserDetails,
)


class UlpfMeta(BaseModel):
    schema_version: str = Field(default="0.1")
    event_id: str


class OriginalLogMeta(BaseModel):
    format: str
    message: str
    sha256: str
    transport: Optional[str] = None


class FieldProvenance(BaseModel):
    """
    Field-level provenance mapping detailing where each canonical field originated.
    """
    original_field: str
    original_value: Any
    parser: str
    confidence: float = 1.0


class UlpfIR(BaseModel):
    """
    Central ULPF Intermediate Representation (ULPF-IR).
    Canonical representation of logs across formats and vendors.
    """
    ulpf: UlpfMeta
    event: EventDetails = Field(default_factory=EventDetails)
    source: SourceDetails = Field(default_factory=SourceDetails)
    destination: DestinationDetails = Field(default_factory=DestinationDetails)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    rule: RuleDetails = Field(default_factory=RuleDetails)
    user: UserDetails = Field(default_factory=UserDetails)
    severity: Optional[str] = None
    original: OriginalLogMeta
    provenance: Dict[str, FieldProvenance] = Field(default_factory=dict)
    status: str = Field(default="success")  # "success", "unparsed", "partial"
    reason: Optional[str] = None
