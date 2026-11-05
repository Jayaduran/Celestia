"""
Kosmoporos: Universal High-Speed Log Preprocessing & Parsing Engine.
Designed to run in ANY framework (FastAPI, Flask, Celery, Kafka, Vector, Lambda, CLI).
"""

from kosmoporos.engine import KosmoporosEngine
from kosmoporos.config import KosmoporosConfig
from kosmoporos.models import (
    ParsedLogResult,
    ThreatVerdict,
    RawEvent,
    CanonicalEvent,
    UlpfMeta,
    OriginalLogMeta,
    ProvenanceRecord,
)
from kosmoporos.threat.threat_detector import ThreatDetector
from kosmoporos.merkle import KosmoporosMerkleVault, MerkleBlock
from kosmoporos.stats import KosmoporosStatsEngine

# Framework & backwards-compatibility aliases
UniversalLogParserEngine = KosmoporosEngine
ParserConfig = KosmoporosConfig

__version__ = "1.0.0"

__all__ = [
    "KosmoporosEngine",
    "KosmoporosConfig",
    "UniversalLogParserEngine",
    "ParserConfig",
    "ParsedLogResult",
    "ThreatVerdict",
    "ThreatDetector",
    "RawEvent",
    "CanonicalEvent",
    "UlpfMeta",
    "OriginalLogMeta",
    "ProvenanceRecord",
    "KosmoporosMerkleVault",
    "MerkleBlock",
    "KosmoporosStatsEngine",
]
