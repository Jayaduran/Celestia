from typing import Any, Optional, List, Dict
from enum import Enum
from pydantic import BaseModel, Field

class EvidenceType(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"

class ParserMetadataInfo(BaseModel):
    id: str
    version: str = "1.0"

class RawSourceLocation(BaseModel):
    raw_event_id: Optional[str] = None
    raw_offset: Optional[int] = None
    raw_length: Optional[int] = None

class ProvenanceRecord(BaseModel):
    """
    Field-level provenance record answering:
    Where did this normalized canonical field come from?
    """
    value: Any
    original_field: str
    original_value: Any
    
    # Extended Provenance Details
    source: RawSourceLocation = Field(default_factory=RawSourceLocation)
    parser: str  # For backwards compatibility and quick reference
    parser_info: Optional[ParserMetadataInfo] = None
    
    rule: Optional[str] = "direct_mapping"
    transformation: Optional[str] = None
    
    evidence_type: EvidenceType = EvidenceType.OBSERVED
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    supporting_fields: List[str] = Field(default_factory=list)
