import abc
import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class BaseConnector(abc.ABC):
    """
    Abstract Base Class for ULPF Log Ingestion Connectors.
    All network, file, REST, and streaming connectors inherit from this interface.
    """

    def __init__(self, name: str, connector_type: str):
        self.name = name
        self.connector_type = connector_type
        self.is_running = False
        self.total_received = 0
        self.total_accepted = 0
        self.total_rejected = 0
        self.total_dropped_rate_limit = 0
        self.total_processed = 0
        self.total_errors = 0
        self.bytes_received = 0
        self.started_at: Optional[str] = None
        self._last_count = 0
        self._last_time = time.time()
        self._current_eps = 0.0

    @abc.abstractmethod
    def start(self) -> None:
        """Start collector service."""
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop collector service."""
        pass

    def calculate_current_eps(self) -> float:
        """Calculate real live Events Per Second throughput."""
        now = time.time()
        elapsed = now - self._last_time
        if elapsed >= 1.0:
            count_delta = self.total_received - self._last_count
            self._current_eps = round(count_delta / elapsed, 2)
            self._last_count = self.total_received
            self._last_time = now
        return self._current_eps

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and statistics."""
        return {
            "name": self.name,
            "connector_type": self.connector_type,
            "source_type": self.connector_type,
            "is_running": self.is_running,
            "status": "RUNNING" if self.is_running else "STOPPED",
            "total_received": self.total_received,
            "total_accepted": self.total_accepted,
            "total_rejected": self.total_rejected,
            "total_dropped_rate_limit": self.total_dropped_rate_limit,
            "total_processed": self.total_processed,
            "total_errors": self.total_errors,
            "bytes_received": self.bytes_received,
            "current_eps": self.calculate_current_eps(),
            "started_at": self.started_at,
        }

    def is_healthy(self) -> bool:
        """Return true if collector is running without fatal errors."""
        return self.is_running


# Backward compatibility alias
BaseCollector = BaseConnector
