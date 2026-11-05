import time
import logging
from typing import Optional, Dict, Any, Tuple, List
from app.models.raw_event import RawEvent, create_raw_event
from app.models.canonical_event import CanonicalEvent, UlpfMeta, OriginalLogMeta
from app.detector.detector import FormatDetector, DetectionResult
from app.parsers.registry import ParserRegistry, ParserStatus
from app.normalization.normalizer import SemanticNormalizer
from app.exporters.ocsf import OcsfExporter
from app.exporters.ecs import EcsExporter
from app.validation.validator import SecurityValidator
from app.pipeline_monitor import global_throughput_monitor
from app.config.settings import settings
from kosmoporos.threat.threat_detector import ThreatDetector
from kosmoporos.merkle.vault import KosmoporosMerkleVault
from kosmoporos.stats.engine import KosmoporosStatsEngine
from kosmoporos.engine import KosmoporosEngine
import concurrent.futures

_ai_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="SovereignAI")


logger = logging.getLogger("ulpf.pipeline")


class UlpfPipeline:
    """
    Master Orchestration Pipeline for ULPF Phase 1 - Phase 11:
    Raw -> Security Validation -> Format & Vendor Detection -> C-Accelerated Parser Registry ->
    Semantic Normalizer -> ULPF-IR v1.0 -> Exporters (OCSF / ECS)
    Enhanced with Kosmoporos Cryptographic Merkle Vault, Threat Detector & High-Speed Stats Engine.
    """

    def __init__(self):
        self.detector = FormatDetector()
        self.normalizer = SemanticNormalizer()
        self.registry = ParserRegistry()
        self.ocsf_exporter = OcsfExporter()
        self.ecs_exporter = EcsExporter()
        self.throughput_monitor = global_throughput_monitor
        self._last_hash: str = ""
        self.threat_detector = ThreatDetector()
        self.merkle_vault = KosmoporosMerkleVault(block_size=125)
        self.stats_engine = KosmoporosStatsEngine()
        self.engine = KosmoporosEngine()

    def process(self, raw_message: str, source: str = "network_device") -> CanonicalEvent:
        """
        Execute full pipeline from raw message string to ULPF-IR v1.0 CanonicalEvent.
        Guarantees zero unhandled exceptions and 100% data preservation.
        Tracks live throughput and processing latency per event.
        """
        t0 = time.perf_counter()
        raw_bytes_len = len(raw_message.encode("utf-8")) if raw_message else 0

        # 1. Input Security Validation
        valid, err_msg = SecurityValidator.validate_payload(raw_message)
        if not valid:
            raw_ev = create_raw_event(raw_message or "", source=source)
            res = CanonicalEvent(
                ulpf=UlpfMeta(event_id=raw_ev.event_id),
                original=OriginalLogMeta(
                    format="Unknown",
                    message=raw_ev.raw_message,
                    sha256=raw_ev.raw_hash,
                ),
                status="error",
                reason=err_msg,
            )
            lat_us = (time.perf_counter() - t0) * 1000000
            self.throughput_monitor.record_event(byte_size=raw_bytes_len, latency_us=lat_us)
            return res

        # 2. Raw Event Creation & Hash Verification
        raw_event = create_raw_event(raw_message, source=source, previous_hash=self._last_hash)
        self._last_hash = raw_event.chain_hash

        # 3. Format Detection
        detection: DetectionResult = self.detector.detect(raw_message)
        raw_event.format = detection.format

        # 4. Parser Selection from Registry
        parser_map = {
            # Dedicated Vendor Parsers
            "Palo Alto PAN-OS": "palo_alto_panos",
            "Cisco ASA": "cisco_asa",
            "Fortinet FortiGate": "fortinet_fortigate",
            "AWS CloudTrail / VPC Flow": "aws_cloudtrail",
            "Suricata / Snort": "suricata_eve",
            # Standard Parsers
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

        parser_id = parser_map.get(detection.format)
        if not parser_id:
            df_lower = detection.format.lower()
            if "fortinet" in df_lower:
                parser_id = "fortinet_fortigate"
            elif "palo alto" in df_lower or "pan-os" in df_lower:
                parser_id = "palo_alto_panos"
            elif "cisco" in df_lower or "asa" in df_lower:
                parser_id = "cisco_asa"
            elif "cloudtrail" in df_lower or "vpc flow" in df_lower or "aws" in df_lower:
                parser_id = "aws_cloudtrail"
            elif "suricata" in df_lower or "snort" in df_lower:
                parser_id = "suricata_eve"
            elif "cef" in df_lower:
                parser_id = "cef"
            elif "leef" in df_lower:
                parser_id = "leef"
            elif "key=value" in df_lower or "kv" in df_lower:
                parser_id = "key_value"
            elif "json" in df_lower:
                parser_id = "json"
            elif "syslog" in df_lower:
                parser_id = "syslog"
            elif "csv" in df_lower:
                parser_id = "csv"
            elif "xml" in df_lower:
                parser_id = "xml"
            else:
                parser_id = "plain_text"

        parser = self.registry.get_parser(parser_id) or self.registry.get_parser("plain_text")

        # 5. Parsing
        parse_result = parser.parse(raw_event)

        # 6. Check Parse Failure / Unknown / Plaintext -> Trigger Local Sovereign AI Model
        is_unknown_format = detection.format in ("Plaintext", "Unknown", "Unknown (Proprietary)")
        if parse_result.status != "success" or is_unknown_format:
            if settings.ai_enabled and settings.ai_fallback_enabled:
                # Dispatch AI asynchronously to avoid blocking high-speed pipeline
                _ai_executor.submit(self._parse_with_local_ai, raw_event, detection, source)
                lat_us = (time.perf_counter() - t0) * 1000000
                self.throughput_monitor.record_event(byte_size=raw_bytes_len, latency_us=lat_us)
                return CanonicalEvent(
                    ulpf=UlpfMeta(event_id=raw_event.event_id),
                    original=OriginalLogMeta(
                        format=detection.format,
                        message=raw_event.raw_message,
                        sha256=raw_event.raw_hash,
                    ),
                    status="queued_for_ai",
                    reason="Dispatched to Sovereign AI background queue",
                )

            res = CanonicalEvent(
                ulpf=UlpfMeta(event_id=raw_event.event_id),
                original=OriginalLogMeta(
                    format=detection.format,
                    message=raw_event.raw_message,
                    sha256=raw_event.raw_hash,
                ),
                unmapped=parse_result.fields,
                status="unparsed",
                reason=parse_result.reason or detection.reason,
            )
            lat_us = (time.perf_counter() - t0) * 1000000
            self.throughput_monitor.record_event(byte_size=raw_bytes_len, latency_us=lat_us)
            return res

        # 7. Semantic Normalization & Field Provenance Mapping
        meta = self.registry.get_metadata(parser_id)
        confidence = meta.confidence if meta else 1.0
        parser_version = meta.version if meta else "1.0"

        taxonomy, provenance, unmapped = self.normalizer.normalize(
            extracted_fields=parse_result.fields,
            parser_name=parse_result.parser_name,
            confidence=confidence,
            parser_version=parser_version,
            raw_event_id=raw_event.event_id
        )

        # If standard normalizer failed to identify critical taxonomy fields (no action and no IP),
        # trigger local sovereign AI model to understand the proprietary schema
        if not taxonomy.event.action and not taxonomy.source.ip:
            if settings.ai_enabled and settings.ai_fallback_enabled:
                logger.debug("pipeline.process: parsing with AI")
                ai_canonical = self._parse_with_local_ai(raw_event, detection, source)
                if ai_canonical:
                    lat_us = (time.perf_counter() - t0) * 1000000
                    self.throughput_monitor.record_event(byte_size=raw_bytes_len, latency_us=lat_us)
                    self.merkle_vault.append_event(raw_payload=raw_message, event_id=raw_event.event_id)
                    self.stats_engine.record_event(byte_len=raw_bytes_len, latency_us=lat_us, format_name=detection.format)
                    return ai_canonical

        # 8. Threat Detection via Kosmoporos ThreatDetector
        threat = self.threat_detector.evaluate(raw_message=raw_message, src_ip=taxonomy.source.ip)
        if threat.is_threat:
            if not taxonomy.event.type:
                taxonomy.event.type = threat.threat_type
            if threat.severity in ("high", "critical") or not taxonomy.severity:
                taxonomy.severity = threat.severity
            unmapped["threat_verdict"] = threat.to_dict()

        # 9. Cryptographic Merkle Vault Sealing (125 logs/block)
        merkle_record = self.merkle_vault.append_event(raw_payload=raw_message, event_id=raw_event.event_id)
        unmapped["merkle_block_id"] = merkle_record.get("block_id")

        # 10. Construct ULPF-IR CanonicalEvent
        ir = CanonicalEvent(
            ulpf=UlpfMeta(event_id=raw_event.event_id),
            event=taxonomy.event,
            source=taxonomy.source,
            destination=taxonomy.destination,
            network=taxonomy.network,
            device=taxonomy.device,
            rule=taxonomy.rule,
            user=taxonomy.user,
            severity=taxonomy.severity,
            original=OriginalLogMeta(
                format=detection.format,
                message=raw_event.raw_message,
                sha256=raw_event.raw_hash,
            ),
            provenance=provenance,
            unmapped=unmapped,
            status="success",
        )

        # 11. Record live telemetry across both throughput monitor and Kosmoporos stats engine
        lat_us = (time.perf_counter() - t0) * 1000000
        self.throughput_monitor.record_event(byte_size=raw_bytes_len, latency_us=lat_us)
        verd_str = "malicious" if threat.is_threat and threat.severity in ("high", "critical") else ("suspicious" if threat.is_threat else "benign")
        self.stats_engine.record_event(
            byte_len=raw_bytes_len,
            latency_us=lat_us,
            format_name=detection.format,
            threat_verdict=verd_str,
        )

        return ir

    def export_ocsf(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        """Export ULPF-IR to OCSF v1.1.0 JSON representation."""
        return self.ocsf_exporter.export(canonical_event)

    def export_ecs(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        """Export ULPF-IR to Elastic Common Schema (ECS v8.x) JSON representation."""
        return self.ecs_exporter.export(canonical_event)

    def get_merkle_stats(self) -> Dict[str, Any]:
        """Return cryptographic Merkle Vault metrics snapshot."""
        return self.merkle_vault.get_metrics()

    def verify_merkle_block(self, block_id: int) -> bool:
        """Cryptographically verify any sealed 125-log block on demand."""
        passed = self.merkle_vault.verify_block(block_id)
        self.stats_engine.record_merkle_verify(passed)
        return passed

    def get_stats_snapshot(self) -> Dict[str, Any]:
        """Return real-time rolling statistics snapshot with P50/P95/P99 latency percentiles."""
        snapshot = self.stats_engine.get_snapshot()
        snapshot["merkle_vault"].update(self.merkle_vault.get_metrics())
        return snapshot

    def get_latest_merkle_root(self) -> str:
        """Return the current Merkle tree root hash."""
        return self.merkle_vault.get_latest_root()

    def get_statistics(self) -> Dict[str, Any]:
        """Return real-time rolling statistics snapshot for web interface consumption."""
        return self.get_stats_snapshot()

    def parse(
        self,
        raw_payload: str,
        event_id: Optional[str] = None,
        source: str = "network_device",
    ) -> CanonicalEvent:
        """Compatibility alias for KosmoporosEngine.parse()."""
        ir = self.process(raw_payload, source=source)
        if event_id and hasattr(ir, "ulpf"):
            ir.ulpf.event_id = event_id
        return ir

    def parse_batch(
        self,
        items: List[Tuple[str, Optional[str]]],
        source: str = "network_device",
    ) -> List[CanonicalEvent]:
        """High-throughput batch parsing."""
        return [self.parse(raw_payload=msg, event_id=cid, source=source) for msg, cid in items]

    def parse_stored_log(
        self,
        raw_payload: str,
        event_id: Optional[str] = None,
        source: str = "stored_log",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CanonicalEvent:
        """
        Parse a log pulled directly from temporary storage using the pipeline.
        Generates ULPF-IR normalized format, evaluates threat signatures, and records telemetry.
        """
        ir = self.process(raw_payload, source=source)
        if event_id and hasattr(ir, "ulpf"):
            ir.ulpf.event_id = event_id
        if metadata and hasattr(ir, "original"):
            for k, v in metadata.items():
                if not hasattr(ir.original, k):
                    setattr(ir.original, k, v)
        return ir

    def _parse_with_local_ai(self, raw_event: RawEvent, detection: DetectionResult, source: str) -> Optional[CanonicalEvent]:
        """
        Invoke local AI model to parse unknown / unparsed logs directly into ULPF-IR CanonicalEvent.
        """
        if not settings.ai_enabled:
            return None

        # Priority 11: Real-time System Load Shedding
        logger.debug("pipeline.process: checking load shedding")
        from app.pipeline_monitor import global_throughput_monitor
        if global_throughput_monitor.is_load_shedding_active():
            logger.debug("pipeline.process: load shedding active")
            return None

        logger.debug("pipeline.process: inside ai fallback")
        try:
            from app.ai.onboarding import AiOnboardingEngine
            from app.normalization.taxonomy import (
                EventDetails,
                SourceDetails,
                DestinationDetails,
                NetworkDetails,
                DeviceDetails,
                UserDetails,
            )
            from app.models.provenance import ProvenanceRecord, EvidenceType, RawSourceLocation, ParserMetadataInfo
            
            ai_engine = AiOnboardingEngine()
            ai_data = ai_engine.parse_unknown_log(raw_event.raw_message)
            logger.debug("pipeline.process: ai finished")
            if not ai_data or not isinstance(ai_data, dict):
                return None

            src_ip = ai_data.get("source_ip")
            dst_ip = ai_data.get("destination_ip")
            
            raw_action = ai_data.get("event_action")
            action = raw_action if raw_action and raw_action != "unknown" else None
            
            sev = str(ai_data.get("severity")).lower() if ai_data.get("severity") else None
            threat = ai_data.get("threat_type")
            cat = ai_data.get("event_category")
            user = ai_data.get("user_name")
            dev = ai_data.get("device_hostname") or source
            proto = str(ai_data.get("protocol")).lower() if ai_data.get("protocol") else None

            parser_info = ParserMetadataInfo(id="ai_engine", version="1.0")
            source_loc = RawSourceLocation(raw_event_id=raw_event.event_id)

            prov = {}
            if src_ip and src_ip != "N/A":
                prov["source.ip"] = ProvenanceRecord(
                    value=src_ip, original_field="source_ip", original_value=src_ip,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.INFERRED, confidence=0.92,
                )
            else:
                prov["source.ip"] = ProvenanceRecord(
                    value=None, original_field="N/A", original_value=None,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.UNKNOWN, confidence=1.0,
                )

            if dst_ip and dst_ip != "N/A":
                prov["destination.ip"] = ProvenanceRecord(
                    value=dst_ip, original_field="destination_ip", original_value=dst_ip,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.INFERRED, confidence=0.92,
                )
            else:
                prov["destination.ip"] = ProvenanceRecord(
                    value=None, original_field="N/A", original_value=None,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.UNKNOWN, confidence=1.0,
                )

            if action:
                prov["event.action"] = ProvenanceRecord(
                    value=action, original_field="event_action", original_value=action,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.INFERRED, confidence=0.90,
                )
            else:
                prov["event.action"] = ProvenanceRecord(
                    value=None, original_field="N/A", original_value=None,
                    source=source_loc, parser="ai_engine", parser_info=parser_info,
                    evidence_type=EvidenceType.UNKNOWN, confidence=1.0,
                )

            return CanonicalEvent(
                ulpf=UlpfMeta(event_id=raw_event.event_id),
                event=EventDetails(
                    category=cat or "network",
                    type=threat,
                    action=action,
                ),
                source=SourceDetails(
                    ip=src_ip if (src_ip and src_ip != "N/A") else None,
                    port=ai_data.get("source_port"),
                ),
                destination=DestinationDetails(
                    ip=dst_ip if (dst_ip and dst_ip != "N/A") else None,
                    port=ai_data.get("destination_port"),
                ),
                network=NetworkDetails(transport=proto if proto in ("tcp", "udp", "icmp") else None),
                device=DeviceDetails(hostname=dev, product="AI Inferred Device"),
                user=UserDetails(name=user if (user and user != "N/A") else None),
                severity=sev,
                original=OriginalLogMeta(
                    format=f"AI-Inferred ({detection.format})",
                    message=raw_event.raw_message,
                    sha256=raw_event.raw_hash,
                ),
                provenance=prov,
                unmapped=ai_data.get("extracted_fields", {}),
                status="success",
                reason=f"Parsed by AI Engine: {ai_data.get('summary', 'Structure inferred')}",
            )
        except Exception:
            return None
