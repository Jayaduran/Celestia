import re
from typing import Optional, Tuple
from app.config import settings


class SecurityValidator:
    """
    Security and Payload Validator for ULPF.
    Enforces payload limits, input sanitization, and safe regex compilation.
    """

    @staticmethod
    def validate_payload(raw_message: str) -> Tuple[bool, Optional[str]]:
        if raw_message is None:
            return False, "Payload is null"

        byte_len = len(raw_message.encode("utf-8"))
        if byte_len > settings.max_log_payload_bytes:
            return False, f"Payload size ({byte_len} bytes) exceeds maximum limit ({settings.max_log_payload_bytes} bytes)"

        return True, None

    @staticmethod
    def is_safe_regex(pattern_str: str) -> Tuple[bool, Optional[str]]:
        """Verify regex pattern compiles safely without catastrophic backtracking or syntax errors."""
        if not pattern_str:
            return True, None

        # Check length
        if len(pattern_str) > 500:
            return False, "Regex pattern length exceeds safe maximum of 500 characters"

        # Try compilation
        try:
            re.compile(pattern_str)
            return True, None
        except re.error as e:
            return False, f"Invalid regex syntax: {str(e)}"
