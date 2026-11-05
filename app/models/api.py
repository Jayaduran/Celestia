from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class LogInputRequest(BaseModel):
    log: str = Field(..., description="Raw log string to be processed")
    source_type: Optional[str] = "network"


class DetectResponse(BaseModel):
    format: str
    confidence: float
    reason: str


class ParseResponse(BaseModel):
    status: str
    format: str
    raw_hash: str
    extracted_fields: Dict[str, Any]
    reason: Optional[str] = None


class NormalizeResponse(BaseModel):
    status: str
    normalized_event: Dict[str, Any]
    provenance: Dict[str, Any]


class ProcessResponse(BaseModel):
    status: str
    detection: DetectResponse
    normalized_event: Dict[str, Any]
    provenance: Dict[str, Any]
    raw_hash: str
    reason: Optional[str] = None
