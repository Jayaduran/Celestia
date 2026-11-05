"""
Python ctypes wrapper for compiled Kosmoporos C Core library.
Provides ultra-high-speed native SHA-256, Merkle Vault (125 logs/block),
SIMD string tokenizer, and rolling statistics.
"""

import os
import sys
import ctypes
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

_dll_path = Path(__file__).parent / "kosmoporos_core.dll"
_so_path = Path(__file__).parent / "kosmoporos_core.so"
_dylib_path = Path(__file__).parent / "kosmoporos_core.dylib"

_lib = None
if sys.platform == "win32" and _dll_path.exists():
    try:
        _lib = ctypes.CDLL(str(_dll_path))
    except Exception:
        pass
elif sys.platform == "darwin" and (_dylib_path.exists() or _so_path.exists()):
    p = _dylib_path if _dylib_path.exists() else _so_path
    try:
        _lib = ctypes.CDLL(str(p))
    except Exception:
        pass
elif _so_path.exists():
    try:
        _lib = ctypes.CDLL(str(_so_path))
    except Exception:
        pass


def is_c_core_available() -> bool:
    return _lib is not None


# C Struct Definitions
class _KosmoporosSlice(ctypes.Structure):
    _fields_ = [
        ("start", ctypes.c_size_t),
        ("length", ctypes.c_size_t),
    ]


class _KosmoporosKvPair(ctypes.Structure):
    _fields_ = [
        ("key", _KosmoporosSlice),
        ("val", _KosmoporosSlice),
    ]


class _KosmoporosFastParseResult(ctypes.Structure):
    _fields_ = [
        ("format", ctypes.c_int),
        ("pri", ctypes.c_int),
        ("timestamp", _KosmoporosSlice),
        ("hostname", _KosmoporosSlice),
        ("app_name", _KosmoporosSlice),
        ("vendor", _KosmoporosSlice),
        ("product", _KosmoporosSlice),
        ("version", _KosmoporosSlice),
        ("event_id", _KosmoporosSlice),
        ("severity", _KosmoporosSlice),
        ("message", _KosmoporosSlice),
        ("kv_count", ctypes.c_size_t),
        ("kv_pairs", _KosmoporosKvPair * 64),
    ]


class _KosmoporosMerkleProofStep(ctypes.Structure):
    _fields_ = [
        ("hash", ctypes.c_uint8 * 32),
        ("is_right", ctypes.c_bool),
    ]


class _KosmoporosMerkleProof(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_size_t),
        ("steps", _KosmoporosMerkleProofStep * 16),
    ]


class _KosmoporosStats(ctypes.Structure):
    _fields_ = [
        ("total_events", ctypes.c_uint64),
        ("total_bytes", ctypes.c_uint64),
        ("total_errors", ctypes.c_uint64),
        ("total_cef", ctypes.c_uint64),
        ("total_syslog", ctypes.c_uint64),
        ("total_json", ctypes.c_uint64),
        ("total_leef", ctypes.c_uint64),
        ("total_kv", ctypes.c_uint64),
        ("total_plaintext", ctypes.c_uint64),
        ("threat_benign", ctypes.c_uint64),
        ("threat_suspicious", ctypes.c_uint64),
        ("threat_malicious", ctypes.c_uint64),
        ("merkle_blocks_sealed", ctypes.c_uint64),
        ("merkle_verifications_passed", ctypes.c_uint64),
        ("merkle_verifications_failed", ctypes.c_uint64),
        ("window_start_time", ctypes.c_double),
        ("window_events", ctypes.c_uint64),
        ("current_eps", ctypes.c_double),
        ("total_latency_us", ctypes.c_double),
    ]


if _lib:
    # SHA-256 bindings
    _lib.kosmoporos_sha256_hex.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    _lib.kosmoporos_sha256_hex.restype = None

    # Merkle Vault bindings
    _lib.kosmoporos_merkle_block_create.argtypes = [ctypes.c_size_t, ctypes.c_uint32]
    _lib.kosmoporos_merkle_block_create.restype = ctypes.c_void_p

    _lib.kosmoporos_merkle_block_free.argtypes = [ctypes.c_void_p]
    _lib.kosmoporos_merkle_block_free.restype = None

    _lib.kosmoporos_merkle_block_append_raw.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    _lib.kosmoporos_merkle_block_append_raw.restype = ctypes.c_bool

    _lib.kosmoporos_merkle_block_append_hex.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.kosmoporos_merkle_block_append_hex.restype = ctypes.c_bool

    _lib.kosmoporos_merkle_block_seal.argtypes = [ctypes.c_void_p]
    _lib.kosmoporos_merkle_block_seal.restype = ctypes.c_bool

    _lib.kosmoporos_merkle_block_get_root_hex.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.kosmoporos_merkle_block_get_root_hex.restype = None

    _lib.kosmoporos_merkle_block_get_proof.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(_KosmoporosMerkleProof)]
    _lib.kosmoporos_merkle_block_get_proof.restype = ctypes.c_bool

    _lib.kosmoporos_merkle_block_verify_integrity.argtypes = [ctypes.c_void_p]
    _lib.kosmoporos_merkle_block_verify_integrity.restype = ctypes.c_bool

    # SIMD parser bindings
    _lib.kosmoporos_detect_format.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    _lib.kosmoporos_detect_format.restype = ctypes.c_int

    _lib.kosmoporos_fast_parse.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(_KosmoporosFastParseResult)]
    _lib.kosmoporos_fast_parse.restype = ctypes.c_bool

    # Stats Engine bindings
    _lib.kosmoporos_stats_init.argtypes = [ctypes.POINTER(_KosmoporosStats)]
    _lib.kosmoporos_stats_init.restype = None

    _lib.kosmoporos_stats_record_event.argtypes = [ctypes.POINTER(_KosmoporosStats), ctypes.c_size_t, ctypes.c_double, ctypes.c_int, ctypes.c_int]
    _lib.kosmoporos_stats_record_event.restype = None

    _lib.kosmoporos_stats_record_merkle_seal.argtypes = [ctypes.POINTER(_KosmoporosStats)]
    _lib.kosmoporos_stats_record_merkle_seal.restype = None

    _lib.kosmoporos_stats_record_merkle_verify.argtypes = [ctypes.POINTER(_KosmoporosStats), ctypes.c_bool]
    _lib.kosmoporos_stats_record_merkle_verify.restype = None

    _lib.kosmoporos_stats_snapshot.argtypes = [ctypes.POINTER(_KosmoporosStats), ctypes.POINTER(_KosmoporosStats)]
    _lib.kosmoporos_stats_snapshot.restype = None


def c_sha256_hex(data: bytes) -> str:
    """Compute SHA-256 using C Core."""
    if not _lib:
        import hashlib
        return hashlib.sha256(data).hexdigest()
    out = ctypes.create_string_buffer(65)
    _lib.kosmoporos_sha256_hex(data, len(data), out)
    return out.value.decode("ascii")


def c_fast_detect_format(raw_log: str) -> str:
    """Fast format detection in C Core."""
    if not _lib:
        return "UNKNOWN"
    b = raw_log.encode("utf-8", errors="replace")
    fmt_int = _lib.kosmoporos_detect_format(b, len(b))
    fmt_map = {
        0: "UNKNOWN",
        1: "CEF",
        2: "LEEF",
        3: "Syslog-RFC5424",
        4: "Syslog-RFC3164",
        5: "JSON",
        6: "Key=Value",
        7: "Plaintext",
    }
    return fmt_map.get(fmt_int, "UNKNOWN")
