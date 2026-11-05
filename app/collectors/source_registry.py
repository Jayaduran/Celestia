import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from app.storage.database import DatabaseManager


class SourceRegistry:
    """
    Source Registry & Access Controller.
    Tracks active, blocked, and degraded log sources with SQLite persistence.
    """

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or DatabaseManager()
        self._sources: Dict[str, Dict[str, Any]] = {}
        self._last_event_times: Dict[str, float] = {}
        self._event_counts: Dict[str, int] = {}
        self._init_default_sources()
        self._load_sources_from_db()

    def _init_default_sources(self):
        """No static dummy sources; devices are dynamically registered upon live connection."""
        pass

    def _load_sources_from_db(self):
        """Hydrate sources from database repository upon startup.
        (Updated: Clears default connected IP devices on server startup per user request)"""
        try:
            self.db.clear_all_sources()
            self._sources = {}
        except Exception:
            pass

    def register_or_update(
        self,
        source_id: str,
        name: Optional[str] = None,
        source_type: str = "Generic Device",
        vendor: str = "Unknown",
        protocol: str = "Syslog",
        address: str = "127.0.0.1",
        expected_format: str = "Unknown",
    ) -> Dict[str, Any]:
        """Register newly observed network device or update existing source record."""
        if source_id in self._sources:
            s = self._sources[source_id]
            s["last_seen"] = datetime.now(timezone.utc).isoformat()
            try:
                self.db.save_source(s)
            except Exception:
                pass
            return s

        src_entry = {
            "source_id": source_id,
            "name": name or source_id,
            "source_type": source_type,
            "vendor": vendor,
            "protocol": protocol,
            "address": address,
            "expected_format": expected_format,
            "status": "ACTIVE",
            "is_blocked": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }
        self._sources[source_id] = src_entry
        self._event_counts[source_id] = 0
        try:
            self.db.save_source(src_entry)
        except Exception:
            pass
        return src_entry

    def update_device(
        self,
        source_id: str,
        name: Optional[str] = None,
        vendor: Optional[str] = None,
        source_type: Optional[str] = None,
        address: Optional[str] = None,
        protocol: Optional[str] = None,
        expected_format: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Explicitly update or rename a device connection on the server."""
        target_entry: Optional[Dict[str, Any]] = None
        if source_id in self._sources:
            target_entry = self._sources[source_id]
        else:
            # Search by IP address or existing name
            for s in self._sources.values():
                if s.get("address") == source_id or s.get("name") == source_id:
                    target_entry = s
                    break

        if not target_entry:
            # Register new source if not previously recorded
            target_entry = self.register_or_update(
                source_id=source_id,
                name=name or source_id,
                vendor=vendor or "Generic",
                source_type=source_type or "Network Device",
                address=address or (source_id if "." in source_id else "127.0.0.1"),
                protocol=protocol or "HTTP REST (:8000)",
                expected_format=expected_format or "Generic",
            )

        if name and name.strip():
            target_entry["name"] = name.strip()
        if vendor and vendor.strip():
            target_entry["vendor"] = vendor.strip()
        if source_type and source_type.strip():
            target_entry["source_type"] = source_type.strip()
        if address and address.strip():
            target_entry["address"] = address.strip()
        if protocol and protocol.strip():
            target_entry["protocol"] = protocol.strip()
        if expected_format and expected_format.strip():
            target_entry["expected_format"] = expected_format.strip()

        target_entry["last_seen"] = datetime.now(timezone.utc).isoformat()
        try:
            self.db.save_source(target_entry)
        except Exception:
            pass
        return target_entry

    def record_event(
        self,
        source_id: str,
        src_ip: Optional[str] = None,
        vendor: Optional[str] = None,
        device_name: Optional[str] = None,
        protocol: Optional[str] = None,
        log_format: Optional[str] = None,
        source_type: Optional[str] = None,
        is_error: bool = False,
    ):
        """Record ingress event for a source and dynamically learn/update device metadata."""
        clean_id = str(source_id or "").strip()
        if ":" in clean_id and not clean_id.startswith("http") and not clean_id.startswith("file:"):
            parts = clean_id.split(":")
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > 1024:
                clean_id = parts[0]

        has_explicit_dev_name = bool(device_name and device_name not in ("unknown", "Generic", "network_device", "api_client", "batch_api"))
        effective_id: str = str(device_name) if (has_explicit_dev_name and device_name) else str(clean_id or (src_ip if src_ip and src_ip != "N/A" else "Network-Device-01"))

        addr = src_ip if (src_ip and src_ip != "N/A") else ("127.0.0.1" if "file:" in str(clean_id) else str(clean_id))
        if ":" in addr and not addr.startswith("http") and not addr.startswith("file:"):
            parts = addr.split(":")
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > 1024:
                addr = parts[0]

        # Check if we already have an existing source entry by ID or by matching IP address
        matched_source = self._sources.get(effective_id)
        if not matched_source and addr and addr not in ("127.0.0.1", "0.0.0.0"):
            for s in self._sources.values():
                if s.get("address") == addr:
                    matched_source = s
                    break

        if not matched_source:
            # Determine source type heuristically or use passed type
            if source_type:
                stype = source_type
            else:
                v_lower = str(vendor or "").lower()
                d_lower = str(device_name or "").lower()
                if any(k in v_lower or k in d_lower for k in ("wifi", "wireless", "meraki", "aruba", "unifi", "hostapd", "ap-", "mr56", "wlan", "ap305")):
                    stype = "Wireless AP"
                elif any(k in v_lower or k in d_lower for k in ("firewall", "fortinet", "fortigate", "palo", "asa", "fgt", "fw")):
                    stype = "Firewall"
                elif any(k in v_lower or k in d_lower for k in ("router", "cisco", "gateway", "juniper", "mikrotik")):
                    stype = "Router"
                elif any(k in v_lower or k in d_lower for k in ("suricata", "ids", "ips", "snort", "crowdstrike", "edr")):
                    stype = "IDS/IPS"
                elif any(k in v_lower or k in d_lower for k in ("linux", "ssh", "auth", "server", "windows", "host", "ubuntu")):
                    stype = "Server"
                elif any(k in v_lower or k in d_lower for k in ("waf", "cloudflare", "aws_waf")):
                    stype = "WAF"
                else:
                    stype = "Network Device"

            proto = protocol or ("Syslog UDP (514/5140)" if ("5140" in str(effective_id) or "514" in str(effective_id)) else ("Syslog TCP (5141)" if "5141" in str(effective_id) else "HTTP REST (:8000)"))
            disp_name = device_name if has_explicit_dev_name else (f"Device-{addr}" if addr != "127.0.0.1" else effective_id)

            self.register_or_update(
                source_id=effective_id,
                name=disp_name,
                source_type=stype,
                vendor=vendor or "Generic",
                protocol=proto,
                address=addr,
                expected_format=log_format or "Generic",
            )
        else:
            s = matched_source
            # Always update device name if explicit name is provided
            if has_explicit_dev_name and device_name:
                s["name"] = device_name
            if vendor and vendor not in ("Unknown", "Generic"):
                s["vendor"] = vendor
            if source_type:
                s["source_type"] = source_type
            if addr and addr not in ("127.0.0.1", "0.0.0.0", "unknown") and s.get("address") in ("127.0.0.1", "0.0.0.0", "unknown"):
                s["address"] = addr
            if log_format and log_format != "Unknown":
                s["expected_format"] = log_format
            if protocol and protocol != "Syslog":
                s["protocol"] = protocol
            s["last_seen"] = datetime.now(timezone.utc).isoformat()
            try:
                self.db.save_source(s)
            except Exception:
                pass

        sid: str = str(matched_source.get("source_id") or effective_id) if matched_source else effective_id
        self._event_counts[sid] = self._event_counts.get(sid, 0) + 1
        self._last_event_times[sid] = time.time()

    def toggle_block(self, source_id: str) -> Tuple[bool, str]:
        """Toggle source blocking state."""
        if source_id not in self._sources:
            self.register_or_update(source_id=source_id)

        current = self._sources[source_id].get("is_blocked", 0)
        new_state = 0 if current else 1
        self._sources[source_id]["is_blocked"] = new_state
        self._sources[source_id]["status"] = "BLOCKED" if new_state else "ACTIVE"
        try:
            self.db.update_source_status(source_id, self._sources[source_id]["status"], new_state)
        except Exception:
            pass
        return bool(new_state), self._sources[source_id]["status"]

    def is_blocked(self, source_id: str) -> bool:
        """Check if source is currently blocked."""
        if source_id in self._sources:
            return bool(self._sources[source_id].get("is_blocked", 0))
        return False

    def remove_source(self, source_id: str) -> bool:
        """Explicitly remove a source from the live registry."""
        if source_id in self._sources:
            del self._sources[source_id]
            self._event_counts.pop(source_id, None)
            self._last_event_times.pop(source_id, None)
            try:
                self.db.delete_source(source_id)
            except Exception:
                pass
            return True
        # Also try matching by address/ip
        for sid, details in list(self._sources.items()):
            if details.get("address") == source_id or details.get("ip") == source_id:
                del self._sources[sid]
                self._event_counts.pop(sid, None)
                self._last_event_times.pop(sid, None)
                try:
                    self.db.delete_source(sid)
                except Exception:
                    pass
                return True
        return False

    def list_sources(self) -> List[Dict[str, Any]]:
        """Return all registered sources with live statistics and IP mappings."""
        results = []
        now = time.time()
        for sid, s in self._sources.items():
            cnt = self._event_counts.get(sid, 0)
            is_bl = bool(s.get("is_blocked", 0))
            last_t = self._last_event_times.get(sid, 0.0)
            is_recent = (now - last_t) < 30.0 if last_t > 0 else False
            status_str = "BLOCKED" if is_bl else ("ACTIVE" if cnt > 0 else "READY")
            rate = 12 if is_recent else 0

            addr = s.get("address", "127.0.0.1")
            clean_addr = addr.replace("http://", "").replace("https://", "")
            address_ip = clean_addr.split(":")[0] if clean_addr else "127.0.0.1"

            results.append({
                "id": sid,
                "name": s.get("name", sid),
                "type": s.get("source_type", "Network Device"),
                "vendor": s.get("vendor", "Generic"),
                "protocol": s.get("protocol", "Syslog"),
                "address": addr,
                "address_ip": address_ip,
                "format": s.get("expected_format", "CEF"),
                "status": status_str,
                "events_received": cnt,
                "events_per_sec": 0 if is_bl else rate,
                "is_blocked": is_bl,
                "last_seen": s.get("last_seen", datetime.now(timezone.utc).isoformat()),
            })
        return results
