import os
import time
import logging
import threading
import urllib.parse
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from xml.sax.saxutils import escape

logger = logging.getLogger("celestia.twilio")


def _format_ip_for_speech(ip: str) -> str:
    """Format an IP address so text-to-speech pronounces each octet clearly."""
    if not ip or ip in ("N/A", "Unknown", "0.0.0.0", "127.0.0.1"):
        return "an unknown host"
    # Replace dots with ' dot ' for natural speech
    return ip.replace(".", " dot ")


class TwilioVoiceNotifier:
    """
    Twilio Voice Alerting Subsystem for Celestia ULPF.
    Dispatches automated voice phone calls when critical security threats or logs are detected.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.call_history: List[Dict[str, Any]] = []
        self._last_call_time: float = 0.0
        self._last_call_by_threat: Dict[str, float] = {}
        self.broadcast_callback = None

    @property
    def account_sid(self) -> Optional[str]:
        from app.config.settings import settings
        val = settings.twilio_account_sid or os.getenv("TWILIO_ACCOUNT_SID")
        return val.strip() if val else None

    @property
    def auth_token(self) -> Optional[str]:
        from app.config.settings import settings
        val = settings.twilio_auth_token or os.getenv("TWILIO_AUTH_TOKEN")
        return val.strip() if val else None

    @property
    def from_number(self) -> Optional[str]:
        from app.config.settings import settings
        val = settings.twilio_from_number or os.getenv("TWILIO_FROM_NUMBER")
        return val.strip() if val else None

    @property
    def to_number(self) -> str:
        from app.config.settings import settings
        val = settings.twilio_to_number or os.getenv("TWILIO_TO_NUMBER", "+17372508034")
        return val.strip()

    @property
    def enabled(self) -> bool:
        from app.config.settings import settings
        return getattr(settings, "twilio_voice_enabled", True)

    @property
    def cooldown_seconds(self) -> int:
        from app.config.settings import settings
        return getattr(settings, "twilio_cooldown_seconds", 60)

    @property
    def target_number(self) -> str:
        return self.to_number

    def is_configured(self) -> bool:
        """Check if active Twilio credentials have been supplied."""
        sid = self.account_sid
        tok = self.auth_token
        from_num = self.from_number
        if not sid or not tok or not from_num:
            return False
        # Filter out common placeholders
        if "XXXX" in sid or "your_" in tok or "XXXX" in from_num:
            return False
        return True

    def build_twiml(self, threat_type: str, src_ip: str, detail: str = "") -> str:
        """
        Construct TwiML XML payload for Twilio text-to-speech voice call.
        """
        spoken_ip = _format_ip_for_speech(src_ip)
        clean_threat = escape(str(threat_type or "Critical Security Threat"))
        clean_detail = escape(str(detail or ""))
        if clean_detail and len(clean_detail) > 120:
            clean_detail = clean_detail[:120] + "..."

        speech_body = (
            f"Attention! Priority security alert from Celestia Log Defense. "
            f"Critical threat detected: {clean_threat}. "
            f"Originating IP: {spoken_ip}. "
            f"Immediate action required. Check your Celestia console now."
        )

        twiml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Response>'
            '<Pause length="1"/>'
            f'<Say voice="alice" language="en-US">{speech_body}</Say>'
            '<Pause length="1"/>'
            '<Hangup/>'
            '</Response>'
        )
        return twiml

    def send_voice_call(
        self,
        threat_type: str,
        src_ip: str,
        detail: str = "",
        to_number: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Initiate a Twilio voice call synchronously.
        """
        if not self.enabled and not force:
            return {
                "status": "disabled",
                "message": "Twilio voice calls are disabled in configuration.",
            }

        target_number = (to_number or self.to_number).strip()
        now = time.time()
        threat_key = f"{threat_type}:{src_ip}"

        # Guard: Non-critical events or routine traffic must not trigger emergency voice phone calls
        non_critical_threats = ("Blocked IP Violation", "Blacklisted Traffic Dropped", "Security", "unknown", "traffic", "Generic", "N/A", "")
        if not force and (threat_type in non_critical_threats or not threat_type):
            logger.info(f"[Twilio Voice] Suppressed call: '{threat_type}' is not a verified critical attack.")
            return {
                "status": "suppressed_non_critical",
                "threat_type": threat_type,
                "src_ip": src_ip,
                "message": f"Voice call suppressed: '{threat_type}' does not meet critical threat threshold.",
            }

        # Presence Check: Avoid voice phone call if an operator or web visitor is actively on the website
        if not force:
            try:
                from app.auth.manager import auth_manager
                is_present, active_info = auth_manager.check_presence()
                if is_present and active_info:
                    active_user = active_info.get("username", "operator")
                    idle_s = active_info.get("idle_seconds", 0)
                    logger.info(
                        f"[Twilio Voice Avoided] Critical threat '{threat_type}' from {src_ip}, "
                        f"but active operator '{active_user}' is monitoring the console ({idle_s}s ago). Voice call avoided."
                    )
                    record = {
                        "call_id": f"AVOIDED-{int(now * 1000)}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "to_number": target_number,
                        "threat_type": threat_type,
                        "src_ip": src_ip,
                        "status": "suppressed_presence",
                        "active_operator": active_user,
                        "idle_seconds": idle_s,
                        "message": f"Voice call avoided: operator '{active_user}' is actively logged in on the web console.",
                    }
                    self._record_history(record)
                    self._notify_broadcast(record)
                    return record
            except Exception as e:
                logger.debug(f"Presence check evaluation: {e}")

        with self.lock:
            # Strict 1-minute (60s) cooldown between repeated voice calls
            if not force:
                time_since_last_call = now - self._last_call_time
                if time_since_last_call < self.cooldown_seconds:
                    remaining_s = max(1, int(self.cooldown_seconds - time_since_last_call))
                    logger.info(
                        f"[Twilio Voice] Throttled repeated call for {threat_type} from {src_ip} "
                        f"(1-minute cooldown: {remaining_s}s remaining of {self.cooldown_seconds}s limit)"
                    )
                    record = {
                        "call_id": f"CALL-{int(now * 1000)}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "to_number": target_number,
                        "threat_type": threat_type,
                        "src_ip": src_ip,
                        "status": "throttled",
                        "remaining_cooldown_seconds": remaining_s,
                        "reason": f"Throttled by 1-minute ({self.cooldown_seconds}s) cooldown guard between repeated calls.",
                    }
                    self._record_history(record)
                    self._notify_broadcast(record)
                    return record

            self._last_call_time = now
            self._last_call_by_threat[threat_key] = now

        twiml_payload = self.build_twiml(threat_type=threat_type, src_ip=src_ip, detail=detail)

        # Check if Twilio is configured with real credentials
        configured = self.is_configured() if callable(self.is_configured) else bool(self.is_configured)
        if not configured:
            logger.warning(
                f"[Twilio Voice Simulation] Critical Threat: '{threat_type}' from {src_ip}! "
                f"Simulated voice call placed to {target_number}. "
                f"Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER in .env to place live phone calls."
            )
            record = {
                "call_id": f"SIM-CALL-{int(now * 1000)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "to_number": target_number,
                "from_number": self.from_number or "+1 (Simulated)",
                "threat_type": threat_type,
                "src_ip": src_ip,
                "status": "simulated",
                "mode": "simulation",
                "call_sid": f"CA_SIMULATED_{int(now)}",
                "message": f"Simulated call dispatched to {target_number} (Add credentials in .env for live carrier calls)",
                "twiml": twiml_payload,
            }
            self._record_history(record)
            self._notify_broadcast(record)
            return record

        # Perform actual HTTP call to Twilio REST API
        record = self._dispatch_carrier_call(
            target_number=target_number,
            twiml_payload=twiml_payload,
            now=now,
            threat_type=threat_type,
            src_ip=src_ip,
        )

        self._record_history(record)
        self._notify_broadcast(record)
        return record

    def _dispatch_carrier_call(
        self,
        target_number: str,
        twiml_payload: str,
        now: float,
        threat_type: str,
        src_ip: str,
    ) -> Dict[str, Any]:
        """Perform external network HTTP call to Twilio REST API."""
        sid = self.account_sid
        token = self.auth_token
        from_num = self.from_number
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"

        # Twilio Trial accounts disallow inline 'Twiml' parameter but allow 'Url'.
        # Using Twilio's official Echo Twimlet endpoint serves our custom XML securely on all tiers.
        encoded_twiml = urllib.parse.quote(twiml_payload)
        echo_url = f"https://twimlets.com/echo?Twiml={encoded_twiml}"

        data = {
            "To": target_number,
            "From": from_num,
            "Url": echo_url,
        }

        try:
            import httpx
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, data=data, auth=(sid, token))
            
            if resp.status_code in (200, 201):
                resp_data = resp.json()
                call_sid = resp_data.get("sid", "N/A")
                call_status = resp_data.get("status", "queued")
                logger.info(f"[Twilio Voice] Voice call successfully queued to {target_number} (SID: {call_sid}, Status: {call_status})")
                return {
                    "call_id": f"CALL-{int(now * 1000)}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "to_number": target_number,
                    "from_number": from_num,
                    "threat_type": threat_type,
                    "src_ip": src_ip,
                    "status": "initiated",
                    "call_sid": call_sid,
                    "carrier_status": call_status,
                    "message": f"Carrier call initiated to {target_number} via Twilio.",
                }
            else:
                error_body = resp.text
                logger.error(f"[Twilio Voice] Failed calling Twilio API: HTTP {resp.status_code} - {error_body}")
                return {
                    "call_id": f"CALL-{int(now * 1000)}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "to_number": target_number,
                    "from_number": from_num,
                    "threat_type": threat_type,
                    "src_ip": src_ip,
                    "status": "failed",
                    "http_status": resp.status_code,
                    "error": error_body,
                }
        except Exception as e:
            logger.error(f"[Twilio Voice] Exception making phone call to {target_number}: {e}")
            return {
                "call_id": f"CALL-{int(now * 1000)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "to_number": target_number,
                "from_number": from_num,
                "threat_type": threat_type,
                "src_ip": src_ip,
                "status": "error",
                "error": str(e),
            }

    def dispatch_critical_threat_call(
        self,
        event_record: Dict[str, Any],
        threat_info: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> None:
        """
        Asynchronously dispatch a voice call in a background daemon thread
        so log ingestion throughput remains at maximum velocity.
        ONLY fires if an actual critical threat verdict is confirmed.
        """
        threat = threat_info or event_record.get("threat")
        if not threat or not isinstance(threat, dict):
            logger.debug("[Twilio Voice] Suppressed dispatch: No security threat detected in event.")
            return

        sev = str(threat.get("severity", "")).lower()
        if sev != "critical":
            logger.debug(f"[Twilio Voice] Suppressed dispatch: Threat severity '{sev}' is not critical.")
            return

        threat_type = threat.get("threat_type") or threat.get("signature") or ""
        non_critical_threats = ("Blocked IP Violation", "Blacklisted Traffic Dropped", "Security", "unknown", "traffic", "Generic", "N/A", "")
        if threat_type in non_critical_threats or not threat_type:
            logger.debug(f"[Twilio Voice] Suppressed dispatch: '{threat_type}' does not meet critical threat criteria.")
            return

        detail = threat.get("detail", "")
        src_ip = event_record.get("src_ip") or "Unknown"

        def _worker():
            try:
                self.send_voice_call(
                    threat_type=threat_type,
                    src_ip=src_ip,
                    detail=detail,
                    force=force,
                )
            except Exception as ex:
                logger.error(f"Error in background Twilio dispatch thread: {ex}")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _record_history(self, record: Dict[str, Any]) -> None:
        with self.lock:
            self.call_history.insert(0, record)
            if len(self.call_history) > 100:
                self.call_history.pop()

    def _notify_broadcast(self, record: Dict[str, Any]) -> None:
        if callable(self.broadcast_callback):
            try:
                self.broadcast_callback({
                    "type": "TWILIO_CALL_ALERT",
                    "data": record,
                })
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metadata for UI/diagnostics."""
        is_cfg = self.is_configured()
        sid = self.account_sid
        masked_sid = (sid[:4] + "..." + sid[-4:]) if (sid and len(sid) > 8) else None
        now = time.time()
        time_since = now - self._last_call_time if self._last_call_time > 0 else 999999
        cooldown_rem = max(0, int(self.cooldown_seconds - time_since)) if self._last_call_time > 0 else 0
        return {
            "enabled": self.enabled,
            "configured": is_cfg,
            "target_number": self.to_number,
            "from_number": self.from_number or "(Not Set)",
            "account_sid_masked": masked_sid,
            "cooldown_seconds": self.cooldown_seconds,
            "cooldown_active": cooldown_rem > 0,
            "cooldown_remaining_seconds": cooldown_rem,
            "total_calls_triggered": len(self.call_history),
            "recent_calls": self.call_history[:15],
        }


# Singleton instance
twilio_voice_notifier = TwilioVoiceNotifier()
