from typing import Dict, Any, Tuple, Optional
from app.normalization.taxonomy import NetworkTaxonomy
from app.normalization.mappings import TAXONOMY_FIELD_MAPPINGS
from app.models.provenance import ProvenanceRecord, EvidenceType, ParserMetadataInfo, RawSourceLocation


class SemanticNormalizer:
    """
    Normalizes vendor/format-specific extracted fields into the canonical NetworkTaxonomy
    and tracks field-level provenance. Preserves unmapped fields into a dedicated dictionary.
    """

    def _find_field(self, extracted: Dict[str, Any], candidates: list) -> Optional[Tuple[str, Any]]:
        for cand in candidates:
            if cand in extracted and extracted[cand] is not None:
                return cand, extracted[cand]

        # Case-insensitive search fallback
        lowered = {k.lower(): (k, v) for k, v in extracted.items() if v is not None}
        for cand in candidates:
            if cand.lower() in lowered:
                orig_k, orig_v = lowered[cand.lower()]
                return orig_k, orig_v

        return None

    def normalize(
        self, extracted_fields: Dict[str, Any], parser_name: str, confidence: float = 1.0, parser_version: str = "1.0", raw_event_id: Optional[str] = None
    ) -> Tuple[NetworkTaxonomy, Dict[str, ProvenanceRecord], Dict[str, Any]]:
        taxonomy = NetworkTaxonomy()
        provenance: Dict[str, ProvenanceRecord] = {}
        mapped_keys = set()
        
        parser_info = ParserMetadataInfo(id=parser_name, version=parser_version)

        def add_provenance(canonical_key: str, val: Any, orig_k: str, orig_v: Any, rule: str, transformation: str = None):
            provenance[canonical_key] = ProvenanceRecord(
                value=val,
                original_field=orig_k,
                original_value=orig_v,
                source=RawSourceLocation(raw_event_id=raw_event_id),
                parser=parser_name,
                parser_info=parser_info,
                rule=rule,
                transformation=transformation,
                evidence_type=EvidenceType.OBSERVED,
                confidence=confidence,
            )
            mapped_keys.add(orig_k)
            
        def add_unknown_provenance(canonical_key: str):
            provenance[canonical_key] = ProvenanceRecord(
                value=None,
                original_field="N/A",
                original_value=None,
                source=RawSourceLocation(raw_event_id=raw_event_id),
                parser=parser_name,
                parser_info=parser_info,
                rule="not_found",
                evidence_type=EvidenceType.UNKNOWN,
                confidence=1.0,
            )

        # 1. Source IP
        res = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["source.ip"])
        if res:
            orig_k, orig_v = res
            taxonomy.source.ip = str(orig_v)
            add_provenance("source.ip", str(orig_v), orig_k, orig_v, "ip_mapping")
        else:
            add_unknown_provenance("source.ip")

        # 2. Source Port
        res = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["source.port"])
        if res:
            orig_k, orig_v = res
            try:
                val_int = int(orig_v)
                taxonomy.source.port = val_int
                add_provenance("source.port", val_int, orig_k, orig_v, "port_mapping", "to_int")
            except (ValueError, TypeError):
                pass
        else:
            add_unknown_provenance("source.port")

        # 2b. Source MAC
        res_smac = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["source.mac"])
        if res_smac:
            orig_k, orig_v = res_smac
            taxonomy.source.mac = str(orig_v)
            add_provenance("source.mac", str(orig_v), orig_k, orig_v, "mac_mapping")

        # 3. Destination IP
        res = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["destination.ip"])
        if res:
            orig_k, orig_v = res
            taxonomy.destination.ip = str(orig_v)
            add_provenance("destination.ip", str(orig_v), orig_k, orig_v, "ip_mapping")
        else:
            add_unknown_provenance("destination.ip")

        # 4. Destination Port
        res = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["destination.port"])
        if res:
            orig_k, orig_v = res
            try:
                val_int = int(orig_v)
                taxonomy.destination.port = val_int
                add_provenance("destination.port", val_int, orig_k, orig_v, "port_mapping", "to_int")
            except (ValueError, TypeError):
                pass
        else:
            add_unknown_provenance("destination.port")

        # 4b. Destination MAC / BSSID
        res_dmac = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["destination.mac"])
        if res_dmac:
            orig_k, orig_v = res_dmac
            taxonomy.destination.mac = str(orig_v)
            add_provenance("destination.mac", str(orig_v), orig_k, orig_v, "mac_mapping")

        # 5. Network Protocol & Transport
        res = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["network.protocol"])
        if res:
            orig_k, orig_v = res
            val_str = str(orig_v).lower()
            if val_str in ["tcp", "udp", "icmp"]:
                taxonomy.network.transport = val_str
                add_provenance("network.transport", val_str, orig_k, orig_v, "transport_mapping", "lowercase")
            else:
                taxonomy.network.protocol = val_str
                add_provenance("network.protocol", val_str, orig_k, orig_v, "proto_mapping", "lowercase")
        else:
            add_unknown_provenance("network.protocol")

        res_trans = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["network.transport"])
        if res_trans:
            orig_k, orig_v = res_trans
            taxonomy.network.transport = str(orig_v).lower()
            add_provenance("network.transport", taxonomy.network.transport, orig_k, orig_v, "transport_mapping", "lowercase")

        # 5b. Wireless Network SSID
        res_ssid = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["network.ssid"])
        if res_ssid:
            orig_k, orig_v = res_ssid
            taxonomy.network.ssid = str(orig_v)
            add_provenance("network.ssid", str(orig_v), orig_k, orig_v, "ssid_mapping")

        # 6. Event Action
        res_act = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["event.action"])
        if res_act:
            orig_k, orig_v = res_act
            taxonomy.event.action = str(orig_v).lower()
            add_provenance("event.action", taxonomy.event.action, orig_k, orig_v, "action_mapping", "lowercase")
        else:
            add_unknown_provenance("event.action")

        # 7. Device Vendor / Product / Hostname
        res_v = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["device.vendor"])
        if res_v:
            orig_k, orig_v = res_v
            taxonomy.device.vendor = str(orig_v)
            add_provenance("device.vendor", str(orig_v), orig_k, orig_v, "vendor_mapping")

        res_p = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["device.product"])
        if res_p:
            orig_k, orig_v = res_p
            taxonomy.device.product = str(orig_v)
            add_provenance("device.product", str(orig_v), orig_k, orig_v, "product_mapping")

        res_h = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["device.hostname"])
        if res_h:
            orig_k, orig_v = res_h
            taxonomy.device.hostname = str(orig_v)
            add_provenance("device.hostname", str(orig_v), orig_k, orig_v, "hostname_mapping")

        # 8. Rule Name & ID
        res_rn = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["rule.name"])
        if res_rn:
            orig_k, orig_v = res_rn
            taxonomy.rule.name = str(orig_v)
            add_provenance("rule.name", str(orig_v), orig_k, orig_v, "rule_name_mapping")

        res_ri = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["rule.id"])
        if res_ri:
            orig_k, orig_v = res_ri
            taxonomy.rule.id = str(orig_v)
            add_provenance("rule.id", str(orig_v), orig_k, orig_v, "rule_id_mapping")

        # 9. User Name
        res_u = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["user.name"])
        if res_u:
            orig_k, orig_v = res_u
            taxonomy.user.name = str(orig_v)
            add_provenance("user.name", str(orig_v), orig_k, orig_v, "user_mapping")

        # 10. Severity
        res_s = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS["severity"])
        if res_s:
            orig_k, orig_v = res_s
            clean_sev = str(orig_v).strip('"\'').lower()
            taxonomy.severity = clean_sev
            add_provenance("severity", clean_sev, orig_k, orig_v, "severity_mapping", "clean_and_lowercase")
        else:
            add_unknown_provenance("severity")

        # Preserve any unmapped extracted fields
        unmapped = {k: v for k, v in extracted_fields.items() if k not in mapped_keys and not k.startswith("_")}

        return taxonomy, provenance, unmapped
