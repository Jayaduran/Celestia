"""
ULPF C-Acceleration Subsystem & ctypes Binding Layer.
Binds high-performance C parsing routines into Python for maximum log ingestion throughput.
Provides graceful, zero-downtime Python fallback if native C library is unavailable.
"""

import os
import sys
import ctypes
import logging
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger("ulpf.c_parser")

MAX_FIELDS = 128
MAX_STR_LEN = 512

# Array types for ctypes
KeysArray = (ctypes.c_char * MAX_STR_LEN) * MAX_FIELDS
ValuesArray = (ctypes.c_char * MAX_STR_LEN) * MAX_FIELDS


class SyslogHeaderStruct(ctypes.Structure):
    _fields_ = [
        ("pri", ctypes.c_int),
        ("facility", ctypes.c_int),
        ("severity", ctypes.c_int),
        ("version", ctypes.c_int),
        ("timestamp", ctypes.c_char * 64),
        ("hostname", ctypes.c_char * 128),
        ("app_name", ctypes.c_char * 128),
        ("proc_id", ctypes.c_char * 64),
        ("msg_id", ctypes.c_char * 64),
        ("message", ctypes.c_char * 4096),
    ]


class CefHeaderStruct(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_int),
        ("device_vendor", ctypes.c_char * 128),
        ("device_product", ctypes.c_char * 128),
        ("device_version", ctypes.c_char * 64),
        ("device_event_class_id", ctypes.c_char * 128),
        ("name", ctypes.c_char * 256),
        ("severity", ctypes.c_char * 32),
        ("extension", ctypes.c_char * 4096),
    ]


class CFastParserEngine:
    """
    Manages loading and invoking C-accelerated log parsing functions via ctypes.
    """

    def __init__(self):
        self._c_lib = None
        self._is_c_loaded = False
        self._load_c_library()

    def _load_c_library(self) -> None:
        """Attempt to compile and load the C shared library."""
        module_dir = Path(__file__).resolve().parent
        c_src = module_dir / "fast_parser.c"
        is_windows = platform.system() == "Windows"
        lib_name = "fast_parser.dll" if is_windows else "fast_parser.so"
        lib_path = module_dir / lib_name

        # 1. Check if compiled library already exists
        if not lib_path.exists() and c_src.exists():
            self._attempt_compilation(c_src, lib_path, is_windows)

        # 2. Load via ctypes if file exists
        if lib_path.exists():
            try:
                self._c_lib = ctypes.CDLL(str(lib_path))
                self._setup_function_signatures()
                self._is_c_loaded = True
                logger.info(f"[CFastParser] Successfully loaded C acceleration library from {lib_path.name}")
                return
            except Exception as e:
                logger.warning(f"[CFastParser] Could not load C dynamic library: {e}. Using native fallback.")

        logger.info("[CFastParser] C shared library not compiled. Operating with high-speed regex engine.")

    def _attempt_compilation(self, c_src: Path, lib_path: Path, is_windows: bool) -> bool:
        """Compile fast_parser.c using available compiler (gcc, clang, or cl)."""
        compilers = [
            ["gcc", "-O3", "-shared", "-fPIC", str(c_src), "-o", str(lib_path)],
            ["clang", "-O3", "-shared", "-fPIC", str(c_src), "-o", str(lib_path)],
        ]
        if is_windows:
            compilers.insert(0, ["gcc", "-O3", "-shared", str(c_src), "-o", str(lib_path)])

        for cmd in compilers:
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                if result.returncode == 0 and lib_path.exists():
                    logger.info(f"[CFastParser] Compiled {lib_path.name} with {cmd[0]}")
                    return True
            except Exception:
                continue
        return False

    def _setup_function_signatures(self) -> None:
        """Define argument and return types for C functions."""
        if not self._c_lib:
            return

        # fast_parse_kv(const char* input, char out_keys[128][512], char out_values[128][512], int max_pairs)
        try:
            self._c_lib.fast_parse_kv.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(KeysArray),
                ctypes.POINTER(ValuesArray),
                ctypes.c_int,
            ]
            self._c_lib.fast_parse_kv.restype = ctypes.c_int
        except Exception:
            pass

        # fast_parse_syslog_header(const char* input, SyslogHeaderResult* out_result)
        try:
            self._c_lib.fast_parse_syslog_header.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(SyslogHeaderStruct),
            ]
            self._c_lib.fast_parse_syslog_header.restype = ctypes.c_int
        except Exception:
            pass

        # fast_parse_cef_header(const char* input, CefHeaderResult* out_result)
        try:
            self._c_lib.fast_parse_cef_header.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(CefHeaderStruct),
            ]
            self._c_lib.fast_parse_cef_header.restype = ctypes.c_int
        except Exception:
            pass

    @property
    def is_accelerated(self) -> bool:
        """Returns True if C-acceleration library is actively engaged."""
        return self._is_c_loaded

    def get_engine_status(self) -> Dict[str, Any]:
        """Return operational status of C acceleration layer."""
        return {
            "c_acceleration": self._is_c_loaded,
            "engine": "C Dynamic Library (fast_parser.dll/.so)" if self._is_c_loaded else "High-Speed Regex Fallback Engine",
            "library_loaded": bool(self._c_lib),
        }

    def parse_kv(self, raw_str: str) -> Dict[str, Any]:
        """
        Fast Key-Value Parser using C extension or high-speed regex fallback.
        """
        if not raw_str:
            return {}

        if self._is_c_loaded and self._c_lib:
            try:
                keys_buf = KeysArray()
                values_buf = ValuesArray()
                b_str = raw_str.encode("utf-8", errors="replace")

                count = self._c_lib.fast_parse_kv(b_str, ctypes.byref(keys_buf), ctypes.byref(values_buf), MAX_FIELDS)
                if count > 0:
                    result = {}
                    for i in range(count):
                        k = keys_buf[i].value.decode("utf-8", errors="replace")
                        v = values_buf[i].value.decode("utf-8", errors="replace")
                        if k:
                            # Auto-convert numbers if possible
                            if v.isdigit():
                                result[k] = int(v)
                            elif v.lower() in ("true", "yes"):
                                result[k] = True
                            elif v.lower() in ("false", "no"):
                                result[k] = False
                            else:
                                result[k] = v
                    return result
            except Exception:
                pass

        # Fast Python Fallback
        import re
        kv_regex = re.compile(r'([a-zA-Z0-9_.-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
        fields = {}
        for match in kv_regex.finditer(raw_str):
            key = match.group(1)
            val = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            if val is not None:
                if val.isdigit():
                    fields[key] = int(val)
                else:
                    fields[key] = val
        return fields

    def parse_cef_header(self, raw_str: str) -> Optional[Dict[str, Any]]:
        """Fast CEF Header extraction."""
        if not raw_str:
            return None

        if self._is_c_loaded and self._c_lib:
            try:
                res_buf = CefHeaderStruct()
                b_str = raw_str.encode("utf-8", errors="replace")
                ok = self._c_lib.fast_parse_cef_header(b_str, ctypes.byref(res_buf))
                if ok:
                    return {
                        "version": res_buf.version,
                        "device_vendor": res_buf.device_vendor.decode("utf-8", errors="replace"),
                        "device_product": res_buf.device_product.decode("utf-8", errors="replace"),
                        "device_version": res_buf.device_version.decode("utf-8", errors="replace"),
                        "device_event_class_id": res_buf.device_event_class_id.decode("utf-8", errors="replace"),
                        "name": res_buf.name.decode("utf-8", errors="replace"),
                        "severity": res_buf.severity.decode("utf-8", errors="replace"),
                        "extension": res_buf.extension.decode("utf-8", errors="replace"),
                    }
            except Exception:
                pass
        return None

    def benchmark(self, iterations: int = 10000) -> Dict[str, Any]:
        """Benchmark KV parsing throughput and latency."""
        import time
        sample = 'src=192.168.1.50 dst=10.0.0.1 action=deny proto=TCP dport=443 sport=54321 vendor=Fortinet app=HTTPS'
        start = time.perf_counter()
        for _ in range(iterations):
            self.parse_kv(sample)
        elapsed = time.perf_counter() - start
        ops_per_sec = iterations / max(0.0001, elapsed)
        time_per_op_us = (elapsed / iterations) * 1_000_000
        return {
            "iterations": iterations,
            "total_time_s": round(elapsed, 4),
            "ops_per_sec": round(ops_per_sec, 1),
            "time_per_op_us": round(time_per_op_us, 2),
            "engine": "C Dynamic Library" if self._is_c_loaded else "High-Speed Regex Fallback Engine"
        }



# Global singleton engine instance
c_fast_parser = CFastParserEngine()
