"""
Kosmoporos Rolling Statistics Engine.
Provides high-frequency, thread-safe statistics for the Kosmoporos parsing unit,
including EPS windowing, byte throughput, latency metrics, format breakdown,
and Merkle Vault integrity status.
"""

import time
import ctypes
from typing import Dict, Any, Optional
from ..c_core.bindings import (
    is_c_core_available,
    _lib,
    _KosmoporosStats,
)


class KosmoporosStatsEngine:
    """Real-time Rolling Statistics Engine for Kosmoporos."""

    def __init__(self):
        self._c_stats = _KosmoporosStats()
        self._has_c = is_c_core_available() and _lib is not None
        if self._has_c:
            _lib.kosmoporos_stats_init(ctypes.byref(self._c_stats))

        # Python tracking fallback/mirror
        self.total_events = 0
        self.total_bytes = 0
        self.total_errors = 0
        self.format_counts: Dict[str, int] = {
            "CEF": 0, "LEEF": 0, "Syslog": 0, "JSON": 0, "Key=Value": 0, "Plaintext": 0
        }
        self.threat_counts: Dict[str, int] = {
            "benign": 0, "suspicious": 0, "malicious": 0
        }
        self.merkle_blocks_sealed = 0
        self.merkle_verifications_passed = 0
        self.merkle_verifications_failed = 0

        self._window_start = time.time()
        self._window_events = 0
        self._current_eps = 0.0
        self._latencies_sample: list = []

    def record_event(
        self,
        byte_len: int,
        latency_us: float,
        format_name: str = "Plaintext",
        threat_verdict: str = "benign",
    ) -> None:
        """Record a single processed log event."""
        self.total_events += 1
        self.total_bytes += byte_len
        self._window_events += 1

        # Keep last 1000 latency samples for percentiles
        if len(self._latencies_sample) >= 1000:
            self._latencies_sample.pop(0)
        self._latencies_sample.append(latency_us)

        fmt_key = format_name
        if "CEF" in fmt_key: fmt_key = "CEF"
        elif "LEEF" in fmt_key: fmt_key = "LEEF"
        elif "Syslog" in fmt_key: fmt_key = "Syslog"
        elif "JSON" in fmt_key: fmt_key = "JSON"
        elif "Key=Value" in fmt_key: fmt_key = "Key=Value"
        else: fmt_key = "Plaintext"
        self.format_counts[fmt_key] = self.format_counts.get(fmt_key, 0) + 1

        tv_key = threat_verdict.lower()
        if tv_key in self.threat_counts:
            self.threat_counts[tv_key] += 1
        else:
            self.threat_counts["benign"] += 1

        now = time.time()
        elapsed = now - self._window_start
        if elapsed >= 1.0:
            self._current_eps = self._window_events / elapsed
            self._window_start = now
            self._window_events = 0

        # Update C Core if loaded
        if self._has_c and _lib:
            fmt_int = 0
            if fmt_key == "CEF": fmt_int = 1
            elif fmt_key == "LEEF": fmt_int = 2
            elif fmt_key == "Syslog": fmt_int = 3
            elif fmt_key == "JSON": fmt_int = 5
            elif fmt_key == "Key=Value": fmt_int = 6
            else: fmt_int = 7

            verd_int = 0
            if tv_key == "suspicious": verd_int = 1
            elif tv_key == "malicious": verd_int = 2

            _lib.kosmoporos_stats_record_event(
                ctypes.byref(self._c_stats),
                byte_len,
                latency_us,
                fmt_int,
                verd_int,
            )

    def record_merkle_seal(self) -> None:
        self.merkle_blocks_sealed += 1
        if self._has_c and _lib:
            _lib.kosmoporos_stats_record_merkle_seal(ctypes.byref(self._c_stats))

    def record_merkle_verify(self, passed: bool) -> None:
        if passed:
            self.merkle_verifications_passed += 1
        else:
            self.merkle_verifications_failed += 1
        if self._has_c and _lib:
            _lib.kosmoporos_stats_record_merkle_verify(ctypes.byref(self._c_stats), passed)

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a complete metrics snapshot for dispatch to web interface."""
        p50 = 0.0
        p95 = 0.0
        p99 = 0.0
        if self._latencies_sample:
            s = sorted(self._latencies_sample)
            p50 = s[int(len(s) * 0.50)]
            p95 = s[int(len(s) * 0.95)]
            p99 = s[min(len(s) - 1, int(len(s) * 0.99))]

        return {
            "total_events": self.total_events,
            "total_bytes": self.total_bytes,
            "total_errors": self.total_errors,
            "current_eps": round(self._current_eps, 2),
            "latency_p50_us": round(p50, 2),
            "latency_p95_us": round(p95, 2),
            "latency_p99_us": round(p99, 2),
            "format_distribution": dict(self.format_counts),
            "threat_distribution": dict(self.threat_counts),
            "merkle_vault": {
                "blocks_sealed": self.merkle_blocks_sealed,
                "verifications_passed": self.merkle_verifications_passed,
                "verifications_failed": self.merkle_verifications_failed,
            },
            "engine_core": "C-Core (Native DLL)" if self._has_c else "Python",
        }
