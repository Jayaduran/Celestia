from typing import Dict, Any, Tuple, Optional
from kosmoporos.normalization.taxonomy import NetworkTaxonomy
from kosmoporos.normalization.mappings import TAXONOMY_FIELD_MAPPINGS
from kosmoporos.models import ProvenanceRecord


class SemanticNormalizer:
    """
    Normalizes vendor/format-specific extracted fields into the canonical NetworkTaxonomy.
    Tracks unmapped fields and field-level confidence.
    """

    def _find_field(self, extracted: Dict[str, Any], candidates: list) -> Optional[Tuple[str, Any]]:
        for cand in candidates:
            if cand in extracted and extracted[cand] is not None:
                return cand, extracted[cand]

        lowered = {k.lower(): (k, v) for k, v in extracted.items() if v is not None}
        for cand in candidates:
            if cand.lower() in lowered:
                orig_k, orig_v = lowered[cand.lower()]
                return orig_k, orig_v

        return None

    def normalize(
        self,
        extracted_fields: Dict[str, Any],
        parser_name: str,
        confidence: float = 1.0,
        parser_version: str = "1.0",
        raw_event_id: Optional[str] = None
    ) -> Tuple[NetworkTaxonomy, Dict[str, Any], Dict[str, Any]]:
        taxonomy = NetworkTaxonomy()
        provenance: Dict[str, Any] = {}
        mapped_keys = set()

        def add_field(canonical_key: str, val: Any, orig_k: str, orig_v: Any, rule: str = "direct_mapping"):
            provenance[canonical_key] = ProvenanceRecord(
                value=val,
                original_field=orig_k,
                original_value=orig_v,
                parser=parser_name,
                rule=rule,
                confidence=confidence,
            )
            mapped_keys.add(orig_k)

        # Source IP & Port & MAC
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("source.ip", []))
        if found:
            orig_k, orig_v = found
            taxonomy.source.ip = str(orig_v).strip()
            add_field("source.ip", taxonomy.source.ip, orig_k, orig_v, "ip_mapping")

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("source.port", []))
        if found:
            orig_k, orig_v = found
            try:
                taxonomy.source.port = int(orig_v)
                add_field("source.port", taxonomy.source.port, orig_k, orig_v, "port_mapping")
            except Exception:
                pass

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("source.mac", []))
        if found:
            orig_k, orig_v = found
            taxonomy.source.mac = str(orig_v).strip()
            add_field("source.mac", taxonomy.source.mac, orig_k, orig_v, "mac_mapping")

        # Destination IP & Port & MAC
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("destination.ip", []))
        if found:
            orig_k, orig_v = found
            taxonomy.destination.ip = str(orig_v).strip()
            add_field("destination.ip", taxonomy.destination.ip, orig_k, orig_v, "ip_mapping")

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("destination.port", []))
        if found:
            orig_k, orig_v = found
            try:
                taxonomy.destination.port = int(orig_v)
                add_field("destination.port", taxonomy.destination.port, orig_k, orig_v, "port_mapping")
            except Exception:
                pass

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("destination.mac", []))
        if found:
            orig_k, orig_v = found
            taxonomy.destination.mac = str(orig_v).strip()
            add_field("destination.mac", taxonomy.destination.mac, orig_k, orig_v, "mac_mapping")

        # Network Protocol & Transport & SSID
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("network.protocol", []))
        if found:
            orig_k, orig_v = found
            val_str = str(orig_v).lower()
            if val_str in ["tcp", "udp", "icmp"]:
                taxonomy.network.transport = val_str
                add_field("network.transport", val_str, orig_k, orig_v, "transport_mapping")
            taxonomy.network.protocol = val_str
            add_field("network.protocol", val_str, orig_k, orig_v, "proto_mapping")

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("network.transport", []))
        if found:
            orig_k, orig_v = found
            taxonomy.network.transport = str(orig_v).lower()
            add_field("network.transport", taxonomy.network.transport, orig_k, orig_v, "transport_mapping")

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("network.ssid", []))
        if found:
            orig_k, orig_v = found
            taxonomy.network.ssid = str(orig_v)
            add_field("network.ssid", taxonomy.network.ssid, orig_k, orig_v, "ssid_mapping")

        # Event Action
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("event.action", []))
        if found:
            orig_k, orig_v = found
            v_low = str(orig_v).lower()
            taxonomy.event.action = v_low
            add_field("event.action", v_low, orig_k, orig_v, "action_mapping")

        # Event Type & Category & Time
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("event.type", []))
        if found:
            orig_k, orig_v = found
            taxonomy.event.type = str(orig_v)
            add_field("event.type", taxonomy.event.type, orig_k, orig_v)

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("event.category", []))
        if found:
            orig_k, orig_v = found
            taxonomy.event.category = str(orig_v)
            add_field("event.category", taxonomy.event.category, orig_k, orig_v)

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("event.time", []))
        if found:
            orig_k, orig_v = found
            taxonomy.event.time = str(orig_v)
            add_field("event.time", taxonomy.event.time, orig_k, orig_v)

        # Device Vendor & Product & Hostname
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("device.vendor", []))
        if found:
            orig_k, orig_v = found
            taxonomy.device.vendor = str(orig_v)
            add_field("device.vendor", taxonomy.device.vendor, orig_k, orig_v)

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("device.product", []))
        if found:
            orig_k, orig_v = found
            taxonomy.device.product = str(orig_v)
            add_field("device.product", taxonomy.device.product, orig_k, orig_v)

        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("device.hostname", []))
        if found:
            orig_k, orig_v = found
            taxonomy.device.hostname = str(orig_v)
            add_field("device.hostname", taxonomy.device.hostname, orig_k, orig_v)

        # Rule Name
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("rule.name", []))
        if found:
            orig_k, orig_v = found
            taxonomy.rule.name = str(orig_v)
            add_field("rule.name", taxonomy.rule.name, orig_k, orig_v)

        # User Name
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("user.name", []))
        if found:
            orig_k, orig_v = found
            taxonomy.user.name = str(orig_v)
            add_field("user.name", taxonomy.user.name, orig_k, orig_v)

        # Severity
        found = self._find_field(extracted_fields, TAXONOMY_FIELD_MAPPINGS.get("severity", []))
        if found:
            orig_k, orig_v = found
            taxonomy.severity = str(orig_v).lower()
            add_field("severity", taxonomy.severity, orig_k, orig_v)

        unmapped = {k: v for k, v in extracted_fields.items() if k not in mapped_keys}
        return taxonomy, provenance, unmapped
