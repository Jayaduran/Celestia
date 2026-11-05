import time
import uuid
import hashlib
from typing import Optional, Dict, Any, List, Tuple
from kosmoporos.config import KosmoporosConfig
from kosmoporos.models import (
    ParsedLogResult,
    ThreatVerdict,
    RawEvent,
    CanonicalEvent,
    UlpfMeta,
    OriginalLogMeta,
    EventDetails,
    SourceDetails,
    DestinationDetails,
    NetworkDetails,
    DeviceDetails,
    UserDetails,
    RuleDetails,
    ProvenanceRecord,
)
from kosmoporos.detector import FormatDetector, DetectionResult
from kosmoporos.parsers import ParserRegistry
from kosmoporos.normalization import SemanticNormalizer
from kosmoporos.threat import ThreatDetector
from kosmoporos.ai import KosmoporosAiEngine
from kosmoporos.exporters import OcsfExporter, EcsExporter
from kosmoporos.merkle import KosmoporosMerkleVault
from kosmoporos.stats import KosmoporosStatsEngine


class KosmoporosEngine:
    """
    Kosmoporos Log Preprocessing & Parsing Engine.
    Autonomous, framework-agnostic engine designed to plug into ANY system:
      - FastAPI / Django / Flask
      - Celery / RQ background workers
      - Kafka / Redpanda consumer loops
      - Vector / Fluentbit / Logstash pipelines
      - AWS Lambda / Cloud Functions / CLI scripts
    """

    def __init__(self, config: Optional[KosmoporosConfig] = None):
        self.config = config or KosmoporosConfig()
        self.detector = FormatDetector()
        self.registry = ParserRegistry()
        self.normalizer = SemanticNormalizer()
        self.ocsf_exporter = OcsfExporter()
        self.ecs_exporter = EcsExporter()

        self._ai_engine = None
        if self.config.ai_enabled:
            self._ai_engine = KosmoporosAiEngine(
                provider=self.config.ai_provider,
                host=self.config.ai_host,
                model=self.config.ai_model,
            )

        self.threat_detector = ThreatDetector(
            blocked_ips=self.config.blocked_ips,
            ai_scorer=self._ai_engine.parse_unknown_log if self._ai_engine else None,
        )
        self._last_hash: str = ""
        self.merkle_vault = KosmoporosMerkleVault(block_size=125)
        self.stats_engine = KosmoporosStatsEngine()

    def parse(
        self,
        raw_payload: str,
        event_id: Optional[str] = None,
        source: str = "network_device",
    ) -> ParsedLogResult:
        """
        High-speed single-log processing pipeline:
        Raw -> Format Detection -> Predefined (C/Regex) -> [AI Fallback] ->
        Semantic Normalization -> Integrated Threat Detection -> ParsedLogResult
        """
        t0 = time.perf_counter()
        raw_msg = raw_payload or ""
        eid = event_id or str(uuid.uuid4())
        raw_hash = hashlib.sha256(raw_msg.encode("utf-8", errors="replace")).hexdigest()

        # 1. Raw Event Structure & Hash Chaining
        raw_event = RawEvent(
            event_id=eid,
            raw_message=raw_msg,
            source=source,
            previous_hash=self._last_hash,
        )
        self._last_hash = raw_event.chain_hash

        # 2. Format & Vendor Detection
        detection: DetectionResult = self.detector.detect(raw_msg)
        raw_event.format = detection.format

        # 3. Parser Selection
        parser_map = {
            "Palo Alto PAN-OS": "palo_alto_panos",
            "Palo Alto PAN-OS (Syslog)": "palo_alto_panos",
            "Cisco ASA": "cisco_asa",
            "Cisco ASA (Syslog)": "cisco_asa",
            "Fortinet FortiGate": "fortinet_fortigate",
            "Fortinet FortiGate (Key=Value)": "fortinet_fortigate",
            "AWS CloudTrail / VPC Flow": "aws_cloudtrail",
            "AWS CloudTrail / VPC Flow (Plaintext)": "aws_cloudtrail",
            "Suricata / Snort": "suricata_eve",
            "Suricata / Snort (Syslog)": "suricata_eve",
            "JSON": "json",
            "Syslog": "syslog",
            "CEF": "cef",
            "LEEF": "leef",
            "Key=Value": "key_value",
            "CSV": "csv",
            "XML": "xml",
            "Plaintext": "plain_text",
            "Unknown (Proprietary)": "plain_text",
            "Unknown": "plain_text",
        }

        parser_id = parser_map.get(detection.format, "plain_text")
        parser = self.registry.get_parser(parser_id) or self.registry.get_parser("plain_text")

        # 4. Predefined Parsing Execution
        parse_result = parser.parse(raw_event)
        parser_used = parser_id

        # 5. On-Board AI Fallback (if format unknown or parsing failed)
        is_unknown = detection.format in ("Plaintext", "Unknown", "Unknown (Proprietary)")
        canonical = None

        if parse_result.status != "success" or is_unknown:
            canonical = CanonicalEvent(
                ulpf=UlpfMeta(event_id=eid),
                original=OriginalLogMeta(
                    format=detection.format,
                    message=raw_msg,
                    sha256=raw_hash,
                ),
                unmapped=parse_result.fields if parse_result else {},
                status="unparsed",
                reason=parse_result.reason if parse_result else detection.reason,
            )

        # 6. Semantic Normalization (if not parsed by AI)
        if not canonical:
            meta = self.registry.get_metadata(parser_id)
            confidence = meta.confidence if meta else 1.0
            parser_version = meta.version if meta else "1.0"

            taxonomy, provenance, unmapped = self.normalizer.normalize(
                extracted_fields=parse_result.fields,
                parser_name=parse_result.parser_name,
                confidence=confidence,
                parser_version=parser_version,
                raw_event_id=eid,
            )

            # Secondary AI Fallback if normalizer found no action and no IP
            if not taxonomy.event.action and not taxonomy.source.ip:
                pass # AI analysis is now handled entirely out-of-band by the Python AI Sidecar

            if not canonical:
                canonical = CanonicalEvent(
                    ulpf=UlpfMeta(event_id=eid),
                    event=EventDetails(
                        id=getattr(taxonomy.event, "id", None),
                        category=taxonomy.event.category,
                        type=taxonomy.event.type,
                        action=taxonomy.event.action,
                        time=getattr(taxonomy.event, "time", None),
                    ),
                    source=SourceDetails(
                        ip=taxonomy.source.ip,
                        port=taxonomy.source.port,
                        mac=taxonomy.source.mac,
                    ),
                    destination=DestinationDetails(
                        ip=taxonomy.destination.ip,
                        port=taxonomy.destination.port,
                        mac=taxonomy.destination.mac,
                    ),
                    network=NetworkDetails(
                        transport=getattr(taxonomy.network, "transport", None),
                        protocol=getattr(taxonomy.network, "protocol", None),
                        ssid=getattr(taxonomy.network, "ssid", None),
                    ),
                    device=DeviceDetails(
                        vendor=getattr(taxonomy.device, "vendor", None),
                        product=getattr(taxonomy.device, "product", None),
                        hostname=getattr(taxonomy.device, "hostname", None),
                    ),
                    rule=RuleDetails(
                        name=getattr(taxonomy.rule, "name", None),
                        id=getattr(taxonomy.rule, "id", None),
                    ),
                    user=UserDetails(
                        name=getattr(taxonomy.user, "name", None),
                    ),
                    severity=getattr(taxonomy, "severity", None),
                    original=OriginalLogMeta(
                        format=detection.format,
                        message=raw_msg,
                        sha256=raw_hash,
                    ),
                    provenance=provenance,
                    unmapped=unmapped,
                    status="success",
                )

        # 7. Integrated Threat Detection
        threat: ThreatVerdict = self.threat_detector.evaluate(
            raw_message=raw_msg,
            src_ip=getattr(canonical.source, "ip", None),
            canonical_event=canonical,
        )

        status_str = "blocked" if threat.is_threat and threat.severity in ("high", "critical") else canonical.status
        lat_us = (time.perf_counter() - t0) * 1_000_000

        # 8. Cryptographic Merkle Vault & Statistics Engine Integration
        merkle_record = self.merkle_vault.append_event(raw_payload=raw_msg, event_id=eid)
        verd_str = "malicious" if threat.is_threat and threat.severity in ("high", "critical") else ("suspicious" if threat.is_threat else "benign")
        self.stats_engine.record_event(
            byte_len=len(raw_msg.encode("utf-8", errors="replace")),
            latency_us=lat_us,
            format_name=canonical.original.format,
            threat_verdict=verd_str,
        )

        return ParsedLogResult(
            event_id=eid,
            status=status_str,
            format=canonical.original.format,
            parser_used=parser_used,
            canonical_event=canonical,
            extracted_fields=parse_result.fields if parse_result else {},
            threat=threat,
            raw_message=raw_msg,
            raw_sha256=raw_hash,
            latency_us=lat_us,
            merkle_root=self.merkle_vault.get_latest_root(),
            merkle_block_id=merkle_record.get("block_id"),
        )

    def parse_stored_log(
        self,
        raw_payload: str,
        event_id: Optional[str] = None,
        source: str = "stored_log",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ParsedLogResult:
        """
        Act directly on a stored/staged log pulled from the temporary storage unit.
        Preserves original metadata, parses fields, checks Merkle integrity, and records statistics.
        """
        result = self.parse(raw_payload=raw_payload, event_id=event_id, source=source)
        if metadata and hasattr(result.canonical_event, "original"):
            for k, v in metadata.items():
                if not hasattr(result.canonical_event.original, k):
                    setattr(result.canonical_event.original, k, v)
        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Return real-time rolling statistics snapshot for web interface consumption."""
        snapshot = self.stats_engine.get_snapshot()
        snapshot["merkle_vault"].update(self.merkle_vault.get_metrics())
        return snapshot

    def verify_merkle_block(self, block_id: int) -> bool:
        """Verify cryptographic integrity of any sealed Merkle block."""
        passed = self.merkle_vault.verify_block(block_id)
        self.stats_engine.record_merkle_verify(passed)
        return passed

    def get_latest_merkle_root(self) -> str:
        """Return the current Merkle tree root hash."""
        return self.merkle_vault.get_latest_root()

    def parse_batch(
        self,
        items: List[Tuple[str, Optional[str]]],
        source: str = "network_device",
    ) -> List[ParsedLogResult]:
        """High-throughput batch parsing."""
        return [self.parse(raw_payload=msg, event_id=cid, source=source) for msg, cid in items]

    def export_ocsf(self, item: Any) -> Dict[str, Any]:
        """Export result to OCSF v1.1.0 format."""
        can = item.canonical_event if hasattr(item, "canonical_event") else item
        return self.ocsf_exporter.export(can)

    def export_ecs(self, item: Any) -> Dict[str, Any]:
        """Export result to Elastic Common Schema (ECS v8.x) format."""
        can = item.canonical_event if hasattr(item, "canonical_event") else item
        return self.ecs_exporter.export(can)

    def _parse_with_ai(
        self, raw_event: RawEvent, detection: DetectionResult, source: str
    ) -> Optional[CanonicalEvent]:
        """On-board AI parser fallback invocation."""
        if not self._ai_engine:
            return None

        try:
            ai_data = self._ai_engine.parse_unknown_log(raw_event.raw_message)
            if not ai_data or not isinstance(ai_data, dict):
                return None

            src_ip = ai_data.get("source_ip")
            dst_ip = ai_data.get("destination_ip")
            raw_action = ai_data.get("event_action")
            action = raw_action if raw_action and raw_action != "unknown" else None
            sev = str(ai_data.get("severity")).lower() if ai_data.get("severity") else None
            threat = ai_data.get("threat_type")
            cat = ai_data.get("event_category") or "network"
            proto = str(ai_data.get("protocol")).lower() if ai_data.get("protocol") else None

            prov: Dict[str, Any] = {}
            if src_ip:
                prov["source.ip"] = ProvenanceRecord(
                    value=src_ip, original_field="source_ip", original_value=src_ip,
                    parser="ai_engine", rule="ai_inference", evidence_type="INFERRED", confidence=0.92,
                )
            if dst_ip:
                prov["destination.ip"] = ProvenanceRecord(
                    value=dst_ip, original_field="destination_ip", original_value=dst_ip,
                    parser="ai_engine", rule="ai_inference", evidence_type="INFERRED", confidence=0.92,
                )
            if action:
                prov["event.action"] = ProvenanceRecord(
                    value=action, original_field="event_action", original_value=action,
                    parser="ai_engine", rule="ai_inference", evidence_type="INFERRED", confidence=0.90,
                )

            return CanonicalEvent(
                ulpf=UlpfMeta(event_id=raw_event.event_id),
                event=EventDetails(category=cat, type=threat, action=action),
                source=SourceDetails(ip=src_ip, port=ai_data.get("source_port")),
                destination=DestinationDetails(ip=dst_ip, port=ai_data.get("destination_port")),
                network=NetworkDetails(transport=proto if proto in ("tcp", "udp", "icmp") else None),
                device=DeviceDetails(hostname=source, product="AI Inferred Device"),
                severity=sev,
                original=OriginalLogMeta(
                    format=f"AI-Inferred ({detection.format})",
                    message=raw_event.raw_message,
                    sha256=raw_event.raw_hash,
                ),
                provenance=prov,
                unmapped=ai_data.get("extracted_fields", {}),
                status="success",
                reason=f"Parsed via Kosmoporos AI: {ai_data.get('summary', 'Structure inferred')}",
            )
        except Exception:
            return None
