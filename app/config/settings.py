import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_DEFAULT_STORAGE_DIR = str(_BASE_DIR / "storage" / "raw")
_DEFAULT_DB_PATH = str(_BASE_DIR / "storage" / "ulpf_metadata.db")
_DEFAULT_LOGS_DIR = str(_BASE_DIR / "storage" / "logs")


class Settings(BaseModel):
    app_name: str = "Universal Log Pre-processing Framework (ULPF)"
    version: str = "1.0.0"
    schema_version: str = "1.0"
    environment: str = Field(default_factory=lambda: os.getenv("ULPF_ENV", "development"))
    mode: str = Field(default_factory=lambda: os.getenv("ULPF_MODE", "DEMO").upper())
    # Simple API key authentication (optional)
    api_key: Optional[str] = Field(default_factory=lambda: os.getenv("ULPF_API_KEY", None))
    debug: bool = Field(default_factory=lambda: os.getenv("ULPF_DEBUG", "false").lower() in ("true", "1", "yes"))

    # API Server Configuration
    api_host: str = Field(default_factory=lambda: os.getenv("ULPF_API_HOST", "0.0.0.0"))
    api_port: int = Field(default_factory=lambda: int(os.getenv("ULPF_API_PORT", "8000")))

    # Syslog UDP Collector Configuration
    syslog_udp_enabled: bool = Field(default_factory=lambda: os.getenv("SYSLOG_UDP_ENABLED", "true").lower() in ("true", "1", "yes"))
    syslog_udp_host: str = Field(default_factory=lambda: os.getenv("SYSLOG_UDP_HOST", "0.0.0.0"))
    syslog_udp_port: int = Field(default_factory=lambda: int(os.getenv("SYSLOG_UDP_PORT", "5140")))

    # Syslog TCP Collector Configuration
    syslog_tcp_enabled: bool = Field(default_factory=lambda: os.getenv("SYSLOG_TCP_ENABLED", "true").lower() in ("true", "1", "yes"))
    syslog_tcp_host: str = Field(default_factory=lambda: os.getenv("SYSLOG_TCP_HOST", "0.0.0.0"))
    syslog_tcp_port: int = Field(default_factory=lambda: int(os.getenv("SYSLOG_TCP_PORT", "5141")))

    # Syslog TLS Architecture
    syslog_tls_enabled: bool = Field(default_factory=lambda: os.getenv("SYSLOG_TLS_ENABLED", "false").lower() in ("true", "1", "yes"))
    syslog_tls_port: int = Field(default_factory=lambda: int(os.getenv("SYSLOG_TLS_PORT", "6514")))
    syslog_tls_certfile: Optional[str] = Field(default_factory=lambda: os.getenv("SYSLOG_TLS_CERTFILE", None))
    syslog_tls_keyfile: Optional[str] = Field(default_factory=lambda: os.getenv("SYSLOG_TLS_KEYFILE", None))

    # File Tail Collector Configuration
    file_collector_enabled: bool = Field(default_factory=lambda: os.getenv("FILE_COLLECTOR_ENABLED", "true").lower() in ("true", "1", "yes"))
    file_watch_dir: str = Field(default_factory=lambda: os.getenv("FILE_WATCH_DIR", _DEFAULT_LOGS_DIR))

    # Ingestion Buffer & Rate Limiting
    # Persistence & SQLite Database
    retention_days: int = Field(default_factory=lambda: int(os.getenv("ULPF_RETENTION_DAYS", "30")))
    max_log_payload_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    rate_limit_per_minute: int = 6000
    max_events_per_second: int = Field(default_factory=lambda: int(os.getenv("MAX_EVENTS_PER_SECOND", "25000")))
    ingress_queue_max_size: int = Field(default_factory=lambda: int(os.getenv("INGRESS_QUEUE_MAX_SIZE", "50000")))

    # Local AI / Ollama Configuration
    ollama_host: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_URL", os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    )
    ai_model_name: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", os.getenv("AI_MODEL_NAME", "qwen2.5:7b"))
    )
    ai_enabled: bool = Field(
        default_factory=lambda: os.getenv("AI_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    ai_provider: str = Field(
        default_factory=lambda: os.getenv("AI_PROVIDER", "three_step").lower()
    )
    ai_model: str = Field(
        default_factory=lambda: os.getenv("AI_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    )
    ai_fallback_enabled: bool = Field(
        default_factory=lambda: os.getenv("AI_FALLBACK_ENABLED", "false").lower() in ("true", "1", "yes")
    )
    ai_confidence_threshold: float = 0.80

    # Redis High-Performance In-Memory Cache & Session Store
    redis_enabled: bool = Field(
        default_factory=lambda: os.getenv("REDIS_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    redis_url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://redis:6379/0")
    )

    # Redpanda / Kafka High-Throughput Streaming Bus Configuration
    redpanda_enabled: bool = Field(
        default_factory=lambda: os.getenv("REDPANDA_ENABLED", "true").lower() in ("true", "1", "yes")
    )
    redpanda_brokers: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_BROKERS", os.getenv("KAFKA_BROKERS", "redpanda:9092,localhost:19092"))
    )
    redpanda_input_topic: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_INPUT_TOPIC", "ulpf-raw-ingress")
    )
    redpanda_output_topic: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_OUTPUT_TOPIC", "ulpf-events-normalized")
    )
    redpanda_alerts_topic: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_ALERTS_TOPIC", "ulpf-alerts")
    )
    redpanda_consumer_group: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_CONSUMER_GROUP", "ulpf-workers")
    )
    redpanda_admin_url: str = Field(
        default_factory=lambda: os.getenv("REDPANDA_ADMIN_URL", "http://redpanda:9644")
    )

    # MinIO / S3 Raw Evidence Storage Configuration
    minio_endpoint: str = Field(
        default_factory=lambda: os.getenv("MINIO_ENDPOINT", os.getenv("MINIO_HOST", "minio:9000"))
    )
    minio_access_key: str = Field(
        default_factory=lambda: os.getenv("MINIO_ACCESS_KEY", os.getenv("MINIO_ROOT_USER", "ulpf_admin"))
    )
    minio_secret_key: str = Field(
        default_factory=lambda: os.getenv("MINIO_SECRET_KEY", os.getenv("MINIO_ROOT_PASSWORD", "ulpf_password_2026"))
    )
    minio_bucket: str = Field(
        default_factory=lambda: os.getenv("MINIO_BUCKET", "ulpf-raw")
    )
    minio_secure: bool = Field(
        default_factory=lambda: os.getenv("MINIO_SECURE", "false").lower() in ("true", "1", "yes")
    )

    # OpenSearch Searchable Representation Configuration
    opensearch_url: str = Field(
        default_factory=lambda: os.getenv("OPENSEARCH_URL", os.getenv("OPENSEARCH_HOST", "http://opensearch:9200"))
    )
    opensearch_index: str = Field(
        default_factory=lambda: os.getenv("OPENSEARCH_INDEX", "ulpf-events")
    )

    # Persistence & Database Configuration (SQLite & PostgreSQL Ready)
    db_type: str = Field(
        default_factory=lambda: os.getenv("DB_TYPE", "sqlite").lower()
    )
    database_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", None)
    )
    db_pool_size: int = Field(
        default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "10"))
    )
    db_timeout: float = Field(
        default_factory=lambda: float(os.getenv("DB_TIMEOUT", "10.0"))
    )
    storage_dir: str = Field(
        default_factory=lambda: os.getenv("STORAGE_DIR", _DEFAULT_STORAGE_DIR)
    )
    db_sqlite_path: str = Field(
        default_factory=lambda: os.getenv("DB_SQLITE_PATH", _DEFAULT_DB_PATH)
    )

    # Multi-Provider AI Model Integration (Ollama, OpenAI, Gemini, Anthropic, HuggingFace, Local ML)
    openai_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", None)
    )
    openai_base_url: str = Field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    )
    gemini_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", None)
    )
    anthropic_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", None)
    )
    huggingface_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("HUGGINGFACE_API_KEY", os.getenv("HF_TOKEN", None))
    )
    ai_timeout_seconds: float = Field(
        default_factory=lambda: float(os.getenv("AI_TIMEOUT_SECONDS", "60.0"))
    )
    ai_enrichment_enabled: bool = Field(
        default_factory=lambda: os.getenv("AI_ENRICHMENT_ENABLED", "false").lower() in ("true", "1", "yes")
    )


settings = Settings()
