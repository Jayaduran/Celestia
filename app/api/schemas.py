from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field


class LogInputRequest(BaseModel):
    log: str = Field(..., description="Raw log message string")
    source: Optional[str] = "network_device"


class IngestRequest(BaseModel):
    """
    Flexible Ingestion Schema for POST /api/v1/ingest.
    Accepts string logs, structured JSON messages, or raw payloads.
    """
    log: Optional[str] = Field(None, description="Raw log text message")
    message: Optional[str] = Field(None, description="Alternative field for log message text")
    source: Optional[str] = Field("api_client", description="Source identifier (e.g. web-server-01, firewall-01)")
    payload: Optional[Dict[str, Any]] = Field(None, description="Structured log object")


class BatchIngestRequest(BaseModel):
    """
    Batch Log Ingestion Request Schema.
    """
    logs: List[Union[str, IngestRequest, Dict[str, Any]]] = Field(..., description="Array of log messages or log objects")
    source: Optional[str] = Field("batch_api_client", description="Default source name")


class SamplesInputRequest(BaseModel):
    sample_logs: List[str] = Field(..., description="10-100 sample unparsed log strings")


class GenerateParserRequest(BaseModel):
    yaml_spec: str = Field(..., description="YAML parser specification string")


class ApproveParserRequest(BaseModel):
    parser_id: str = Field(..., description="Parser ID to approve")


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
    unmapped: Dict[str, Any]


class ProcessResponse(BaseModel):
    status: str
    detection: DetectResponse
    canonical_event: Dict[str, Any]
    provenance: Dict[str, Any]
    ocsf_export: Dict[str, Any]
    ecs_export: Dict[str, Any]
    raw_hash: str
    reason: Optional[str] = None


class IngestResponse(BaseModel):
    status: str
    message: str
    event_id: str
    raw_sha256: str
    detected_format: str
    forwarded: bool
    canonical_event: Dict[str, Any]
    ocsf_export: Dict[str, Any]
    ecs_export: Dict[str, Any]


class BatchIngestResponse(BaseModel):
    status: str
    total_received: int
    total_processed: int
    total_success: int
    total_unparsed: int
    events: List[Dict[str, Any]]


class FileUploadResponse(BaseModel):
    status: str
    filename: str
    bytes_received: int
    lines_processed: int
    success_count: int
    unparsed_count: int
    sample_events: List[Dict[str, Any]]


class CollectorStatusResponse(BaseModel):
    api_collector: Dict[str, Any]
    syslog_collector: Dict[str, Any]
    file_collector: Dict[str, Any]
    downstream_forwarder: Dict[str, Any]
