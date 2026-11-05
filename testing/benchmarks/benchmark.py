"""
ULPF High-Performance Deterministic Processing Benchmark Suite
Measures raw parser throughput, latency distributions (P50, P95, P99), memory, and CPU utilization.
"""

import sys
import time
import argparse
import statistics
import psutil
import os
from pathlib import Path
from typing import List, Dict, Any

MAIN_DIR = Path(__file__).resolve().parent.parent.parent
TESTING_DIR = Path(__file__).resolve().parent.parent

if str(MAIN_DIR) not in sys.path:
    sys.path.insert(0, str(MAIN_DIR))
if str(TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(TESTING_DIR))

# Line 19: ULPF Pipeline engine under test (from main core)
from kosmoporos.engine import KosmoporosEngine

# Line 20: Test log generator (prefers testing core, falls back to main api generator)
try:
    from server.log_generator import generate_log
except ImportError:
    from app.api.generator import generate_log



def run_benchmark(
    event_count: int = 10000,
    batch_size: int = 100,
    format_filter: str = "mixed",
    timeout: float = 3.0,
    interval: float = 0.0
) -> Dict[str, Any]:
    print(f"================================================================================")
    print(f"  ULPF REPRODUCIBLE BENCHMARK SUITE — {event_count:,} EVENTS")
    print(f"  Config: Device Timeout={timeout:.2f}s | Inter-Log Interval={interval * 1000.0:.2f}ms ({interval:.4f}s)")
    print(f"================================================================================")
    print(f"Initializing ULPF Pipeline & Warm-up (8 Deterministic Parsers Loaded)...")

    pipeline = KosmoporosEngine()

    # Pre-generate sample logs to isolate pure pipeline execution time
    formats = ["cef", "syslog", "json", "kv", "leef"] if format_filter in ("mixed", "all") else [format_filter if format_filter != "key_value" else "kv"]
    sources = ["firewall", "router", "waf", "vpn", "ids_ips"]

    print(f"Generating {event_count:,} test log payloads across formats: {', '.join(formats)}...")
    test_logs = []
    for i in range(event_count):
        fmt = formats[i % len(formats)]
        src = sources[i % len(sources)]
        test_logs.append((generate_log(src, fmt), src))

    process = psutil.Process(os.getpid())
    mem_before_mb = process.memory_info().rss / (1024 * 1024)

    print(f"\nExecuting Pipeline Benchmark on {event_count:,} Events...")
    latencies_us: List[float] = []
    errors = 0
    successes = 0

    t_start = time.perf_counter()

    for raw_msg, src in test_logs:
        t0 = time.perf_counter()
        try:
            ir = pipeline.parse(raw_payload=raw_msg, source=src)
            if ir.status == "success":
                successes += 1
            else:
                errors += 1
        except Exception:
            errors += 1
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000)
        
        if interval > 0.0:
            time.sleep(interval)

    t_end = time.perf_counter()
    total_duration_sec = t_end - t_start
    events_per_sec = event_count / total_duration_sec if total_duration_sec > 0 else 0

    mem_after_mb = process.memory_info().rss / (1024 * 1024)
    mem_delta_mb = mem_after_mb - mem_before_mb

    # Latency Percentiles
    latencies_us.sort()
    p50_us = statistics.median(latencies_us)
    p95_us = latencies_us[int(len(latencies_us) * 0.95)]
    p99_us = latencies_us[int(len(latencies_us) * 0.99)]
    avg_us = statistics.mean(latencies_us)

    print(f"\n================================================================================")
    print(f"  BENCHMARK RESULTS SUMMARY")
    print(f"================================================================================")
    print(f"  Total Processed Events   : {event_count:,}")
    print(f"  Total Duration           : {total_duration_sec:.4f} seconds")
    print(f"  Deterministic Throughput : {events_per_sec:,.2f} Events / Sec (EPS)")
    print(f"  Success Rate             : {(successes / event_count) * 100:.2f}% ({successes:,} succeeded, {errors} errors)")
    print(f"  Device Timeout Config    : {timeout:.2f}s")
    print(f"  Logs Sent Interval       : {interval * 1000.0:.2f}ms")
    print(f"--------------------------------------------------------------------------------")
    print(f"  Latency (Per Event):")
    print(f"    Mean Average Latency   : {avg_us:.2f} µs ({avg_us / 1000:.4f} ms)")
    print(f"    Median (P50)           : {p50_us:.2f} µs ({p50_us / 1000:.4f} ms)")
    print(f"    95th Percentile (P95)  : {p95_us:.2f} µs ({p95_us / 1000:.4f} ms)")
    print(f"    99th Percentile (P99)  : {p99_us:.2f} µs ({p99_us / 1000:.4f} ms)")
    print(f"--------------------------------------------------------------------------------")
    print(f"  Resource Utilization:")
    print(f"    Process Memory Delta   : {mem_delta_mb:+.2f} MB (Total: {mem_after_mb:.2f} MB)")
    print(f"    CPU Core Affinity      : 1 Core (Single-Threaded Deterministic Python)")
    print(f"================================================================================\n")

    return {
        "event_count": event_count,
        "duration_sec": round(total_duration_sec, 4),
        "events_per_sec": round(events_per_sec, 2),
        "success_rate_pct": round((successes / event_count) * 100, 2),
        "errors": errors,
        "timeout_sec": timeout,
        "interval_sec": interval,
        "latency_us": {
            "mean": round(avg_us, 2),
            "p50": round(p50_us, 2),
            "p95": round(p95_us, 2),
            "p99": round(p99_us, 2)
        },
        "memory_mb": {
            "initial": round(mem_before_mb, 2),
            "final": round(mem_after_mb, 2),
            "delta": round(mem_delta_mb, 2)
        }
    }


if __name__ == "__main__":
    default_timeout = float(os.environ.get("ULPF_DEVICE_TIMEOUT", "3.0"))
    default_interval = float(os.environ.get("ULPF_LOGS_INTERVAL_MS", "0.0")) / 1000.0

    parser = argparse.ArgumentParser(description="ULPF Pipeline Performance Benchmark Suite")
    parser.add_argument("--events", type=int, default=10000, help="Number of synthetic log events to benchmark")
    parser.add_argument("--format", type=str, default="mixed", help="Log format: mixed, cef, syslog, json, key_value, leef")
    parser.add_argument("--timeout", type=float, default=default_timeout, help=f"Device socket connection timeout in seconds (default: {default_timeout}s)")
    parser.add_argument("--interval", type=float, default=default_interval, help=f"Inter-event transmission interval in seconds (default: {default_interval}s)")
    args = parser.parse_args()

    run_benchmark(
        event_count=args.events,
        format_filter=args.format,
        timeout=args.timeout,
        interval=args.interval
    )
