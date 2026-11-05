#!/usr/bin/env python3
"""
ULPF Unified Testing & Verification Pipeline Runner.
Executes the full automated testing suite across the decoupled architecture:
  1. Pytest Test Suites (13 suites, 61 unit/integration tests)
  2. End-to-End Smoke Test Suite (10 verification phases)
  3. Security & Resilience Smoke Test Suite (8 injection/resilience tests)
  4. Stack & Subsystem Verification (10 Docker/AI/Redpanda/API checks)
  5. High-Throughput Ingestion Benchmark (10,000+ events)
"""

import sys
import os
import time
import argparse
import subprocess
from pathlib import Path

# Resolve root, main, and testing directories
ROOT_DIR = Path(__file__).resolve().parent.parent
MAIN_DIR = ROOT_DIR
TESTING_DIR = ROOT_DIR / "testing"

# Ensure main and testing are in sys.path
for p in [ROOT_DIR, MAIN_DIR, TESTING_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Ensure storage directories default to main/storage
os.environ.setdefault("STORAGE_DIR", str(MAIN_DIR / "storage" / "raw"))
os.environ.setdefault("DB_SQLITE_PATH", str(MAIN_DIR / "storage" / "ulpf_metadata.db"))
os.environ.setdefault("FILE_WATCH_DIR", str(MAIN_DIR / "storage" / "logs"))


def run_stage(title: str, cmd: list[str], cwd: Path = ROOT_DIR, device_timeout: float = 3.0, logs_interval_sec: float = 0.01) -> tuple[bool, float, str]:
    """Execute a single pipeline stage and return (success, duration, output)."""
    print("\n" + "=" * 75)
    print(f"  RUNNING STAGE: {title}")
    print(f"  Command: {' '.join(cmd)}")
    print(f"  Stage Config: Device Timeout={device_timeout}s | Logs Interval={logs_interval_sec * 1000.0:.1f}ms")
    print("=" * 75)
    
    start_time = time.time()
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{MAIN_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["ULPF_DEVICE_TIMEOUT"] = str(device_timeout)
    env["ULPF_LOGS_INTERVAL_MS"] = str(round(logs_interval_sec * 1000.0, 2))
    
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=False,
            text=True,
            check=False
        )
        duration = time.time() - start_time
        success = (proc.returncode == 0)
        return success, duration, f"Exit code: {proc.returncode}"
    except Exception as e:
        duration = time.time() - start_time
        return False, duration, str(e)


def main():
    default_timeout = float(os.environ.get("ULPF_DEVICE_TIMEOUT", "3.0"))
    default_interval_sec = float(os.environ.get("ULPF_LOGS_INTERVAL_MS", "0.0")) / 1000.0

    parser = argparse.ArgumentParser(
        description="ULPF Unified Testing & Verification Pipeline"
    )
    parser.add_argument("--all", action="store_true", default=True, help="Run all pipeline stages (default)")
    parser.add_argument("--suites", action="store_true", help="Run only pytest test suites")
    parser.add_argument("--smoke", action="store_true", help="Run only end-to-end smoke test")
    parser.add_argument("--security", action="store_true", help="Run only security smoke test")
    parser.add_argument("--stack", action="store_true", help="Run only stack verification")
    parser.add_argument("--bench", action="store_true", help="Run only throughput benchmark")
    parser.add_argument("--bench-events", type=int, default=10000, help="Number of benchmark events (default: 10000)")
    parser.add_argument("--fast", action="store_true", help="Run fast smoke & security tests without full pytest")
    parser.add_argument("--device-timeout", type=float, default=default_timeout, help=f"Device socket connection/transmission timeout in seconds (default: {default_timeout}s)")
    parser.add_argument("--logs-interval", type=float, default=default_interval_sec, help=f"Inter-log sending interval pacing in seconds (default: {default_interval_sec}s = {default_interval_sec*1000:.1f}ms)")
    parser.add_argument("--logs-interval-ms", type=float, default=None, help="Inter-log sending interval in milliseconds (overrides --logs-interval if specified)")
    
    args = parser.parse_args()

    # Normalize interval
    logs_interval_sec = (args.logs_interval_ms / 1000.0) if args.logs_interval_ms is not None else args.logs_interval
    device_timeout = args.device_timeout

    # Propagate to current environment
    os.environ["ULPF_DEVICE_TIMEOUT"] = str(device_timeout)
    os.environ["ULPF_LOGS_INTERVAL_MS"] = str(round(logs_interval_sec * 1000.0, 2))

    # Determine which stages to run
    run_all = args.all and not (args.suites or args.smoke or args.security or args.stack or args.bench or args.fast)
    
    stages_to_run = []
    
    if args.fast:
        stages_to_run.append(("End-to-End Smoke Test", [sys.executable, str(TESTING_DIR / "smoke_test.py")]))
        stages_to_run.append(("Security & Resilience Smoke Test", [sys.executable, str(TESTING_DIR / "security" / "security_smoke_test.py")]))
        stages_to_run.append(("Stack Subsystem Verification", [sys.executable, str(ROOT_DIR / "scripts" / "verify_stack.py")]))
    else:
        if run_all or args.suites:
            stages_to_run.append(("Pytest Test Suites (13 Suites)", [sys.executable, "-m", "pytest", "testing/suites/"]))
        if run_all or args.smoke:
            stages_to_run.append(("End-to-End Smoke Test", [sys.executable, str(TESTING_DIR / "smoke_test.py")]))
        if run_all or args.security:
            stages_to_run.append(("Security & Resilience Smoke Test", [sys.executable, str(TESTING_DIR / "security" / "security_smoke_test.py")]))
        if run_all or args.stack:
            stages_to_run.append(("Stack Subsystem Verification", [sys.executable, str(ROOT_DIR / "scripts" / "verify_stack.py")]))
        if run_all or args.bench:
            stages_to_run.append((
                "Ingestion Throughput Benchmark",
                [
                    sys.executable,
                    str(TESTING_DIR / "benchmarks" / "benchmark.py"),
                    "--events", str(args.bench_events),
                    "--timeout", str(device_timeout),
                    "--interval", str(logs_interval_sec)
                ]
            ))

    print("\n" + "#" * 75)
    print("      ULPF UNIFIED AUTOMATED TESTING PIPELINE")
    print("      Architecture: Decoupled Main Core & Dedicated Testing Hub")
    print(f"      Selected Stages       : {len(stages_to_run)}")
    print(f"      Device Socket Timeout : {device_timeout:.2f}s")
    print(f"      Logs Sent Interval    : {logs_interval_sec * 1000.0:.1f}ms ({logs_interval_sec:.4f}s)")
    print("#" * 75)

    pipeline_start = time.time()
    results = []
    
    for title, cmd in stages_to_run:
        success, duration, detail = run_stage(title, cmd, device_timeout=device_timeout, logs_interval_sec=logs_interval_sec)
        results.append((title, success, duration, detail))

    total_duration = time.time() - pipeline_start
    all_passed = all(r[1] for r in results)

    print("\n" + "=" * 75)
    print("                   ULPF PIPELINE EXECUTION SUMMARY")
    print("=" * 75)
    print(f"  {'Stage':<42} | {'Status':<8} | {'Duration':<10}")
    print("-" * 75)
    for title, success, duration, _ in results:
        status_str = "[PASS]" if success else "[FAIL]"
        print(f"  {title:<42} | {status_str:<8} | {duration:>6.2f}s")
    print("=" * 75)
    print(f"  Total Pipeline Duration : {total_duration:.2f}s")
    print(f"  Total Stages Executed   : {len(results)}")
    print(f"  Passed Stages           : {sum(1 for r in results if r[1])}")
    print(f"  Failed Stages           : {sum(1 for r in results if not r[1])}")
    
    if all_passed:
        print("=" * 75)
        print("  >>> OVERALL VERDICT: ALL PIPELINE STAGES PASSED [OK] <<<")
        print("=" * 75 + "\n")
        sys.exit(0)
    else:
        print("=" * 75)
        print("  >>> OVERALL VERDICT: PIPELINE FAILED [ERROR] <<<")
        print("=" * 75 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
