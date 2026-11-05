import os
from dataclasses import dataclass, field
from typing import Set, Optional


@dataclass
class KosmoporosConfig:
    """
    Configuration for the Kosmoporos Log Parsing Engine.
    Fully self-contained: can be configured via constructor arguments or .from_env().
    Zero required external dependencies or global settings.
    """
    ai_enabled: bool = True
    ai_fallback_enabled: bool = True
    ai_provider: str = "ollama"
    ai_host: str = "http://127.0.0.1:11434"
    ai_model: str = "qwen2.5-coder:7b"
    c_acceleration: bool = True
    threat_detection: bool = True
    blocked_ips: Set[str] = field(default_factory=set)

    @classmethod
    def from_env(cls) -> "KosmoporosConfig":
        """Instantiate config with optional environment variable overrides."""
        ai_enabled = os.getenv("KOSMOPOROS_AI_ENABLED", "true").lower() in ("true", "1", "yes")
        ai_fallback = os.getenv("KOSMOPOROS_AI_FALLBACK", "true").lower() in ("true", "1", "yes")
        ai_provider = os.getenv("KOSMOPOROS_AI_PROVIDER", "ollama").lower()
        ai_host = os.getenv("KOSMOPOROS_AI_HOST", os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
        ai_model = os.getenv("KOSMOPOROS_AI_MODEL", os.getenv("AI_MODEL_NAME", "qwen2.5-coder:7b"))
        c_accel = os.getenv("KOSMOPOROS_C_ACCEL", "true").lower() in ("true", "1", "yes")
        threat_det = os.getenv("KOSMOPOROS_THREAT_DETECTION", "true").lower() in ("true", "1", "yes")

        blocked_str = os.getenv("KOSMOPOROS_BLOCKED_IPS", "")
        blocked_ips = {ip.strip() for ip in blocked_str.split(",") if ip.strip()}

        return cls(
            ai_enabled=ai_enabled,
            ai_fallback_enabled=ai_fallback,
            ai_provider=ai_provider,
            ai_host=ai_host,
            ai_model=ai_model,
            c_acceleration=c_accel,
            threat_detection=threat_det,
            blocked_ips=blocked_ips,
        )
