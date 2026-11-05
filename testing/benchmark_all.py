import sys
import os
import time
import json
import statistics

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.raw_event import RawEvent
from app.parsers import (
    PaloAltoParser,
    CiscoAsaParser,
    FortinetParser,
    AwsCloudtrailParser,
    SuricataParser,
    SyslogParser,
    JsonParser,
    CefParser,
    LeefParser,
    KvParser,
)
from app.parsers.c_fast_parser import c_fast_parser
from kosmoporos.engine import KosmoporosEngine
from app.pipeline_monitor import ThroughputMonitor

def run_benchmarks(iterations=5000):
    print("=" * 80, flush=True)
    print(f"       ULPF COMPREHENSIVE BENCHMARK SUITE ({iterations:,} iterations each)", flush=True)
    print("=" * 80, flush=True)

    # 1. C-Parser Engine benchmark
    c_bench = c_fast_parser.benchmark(iterations=iterations)
    print(f"\n[1] C / ctypes Acceleration Engine:", flush=True)
    print(f"    Engine Type   : {c_bench['engine']}", flush=True)
    print(f"    Throughput    : {c_bench['ops_per_sec']:,.0f} ops/sec", flush=True)
    print(f"    Latency       : {c_bench['time_per_op_us']} µs/op", flush=True)
    print(f"    Total Time    : {c_bench['total_time_s']:.3f} s", flush=True)

    # Sample logs for individual parsers
    test_samples = {
        "Fortinet FortiGate (KV)": (
            FortinetParser(),
            'date=2026-09-12 time=17:00:00 devname="FGT-CORE-01" devid="FG100E" type="traffic" subtype="forward" level="notice" action="accept" srcip=10.0.1.25 dstip=8.8.8.8 srcport=49210 dstport=53 proto=17 app="DNS" sentbyte=320 rcvdbyte=1450'
        ),
        "Palo Alto PAN-OS (CSV)": (
            PaloAltoParser(),
            '1,2026/09/12 17:00:00,001801000001,TRAFFIC,drop,1,2026/09/12 17:00:00,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Deny,,,ping,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward,2026/09/12 17:00:00,1,1,60,0,0,0,0,0x0,icmp,deny,60,60,0,1,2026/09/12 17:00:00,0,any,0,0,0,0,,US,IN,0,1,0,policy-deny,0,0,0,0,,PA-5220,from-policy'
        ),
        "Cisco ASA (Syslog)": (
            CiscoAsaParser(),
            '%ASA-4-106023: Deny tcp src outside:198.51.100.19/52140 dst inside:10.0.1.50/443 by access-group "OUTSIDE_IN" [0x0, 0x0]'
        ),
        "AWS CloudTrail (JSON)": (
            AwsCloudtrailParser(),
            json.dumps({
                "eventVersion": "1.08",
                "eventTime": "2026-09-12T17:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.88",
                "userAgent": "aws-cli/2.15.0",
                "userIdentity": {"type": "IAMUser", "userName": "alice_admin", "accountId": "123456789012"},
                "responseElements": {"user": {"userName": "contractor_bob"}}
            })
        ),
        "Suricata EVE (JSON)": (
            SuricataParser(),
            json.dumps({
                "timestamp": "2026-09-12T17:00:00.123456+0000",
                "event_type": "alert",
                "src_ip": "185.220.101.5",
                "src_port": 41250,
                "dest_ip": "10.0.1.10",
                "dest_port": 22,
                "proto": "TCP",
                "alert": {
                    "action": "blocked",
                    "signature_id": 2010935,
                    "signature": "ET SCAN Potential SSH BruteForce Detected",
                    "category": "Attempted Information Leak",
                    "severity": 1
                }
            })
        ),
        "Standard Syslog RFC5424": (
            SyslogParser(),
            '<134>1 2026-09-12T17:00:00Z host-01 sshd 1234 - - Failed password for root from 192.168.1.50 port 22'
        ),
        "Standard CEF Header": (
            CefParser(),
            'CEF:0|SecurityVendor|NGFW|9.0|100|Deny Traffic|6|src=192.168.1.100 dst=10.0.0.1 dpt=443 proto=tcp act=deny'
        ),
        "Standard LEEF 2.0": (
            LeefParser(),
            'LEEF:2.0|Microsoft|MSExchange|2013|AuthFail|src=10.0.1.5 dst=10.0.0.2 usr=admin act=blocked'
        ),
        "Generic Key-Value": (
            KvParser(),
            'timestamp=2026-09-12T17:00:00Z src=192.168.1.100 dst=10.0.0.1 proto=TCP action=drop dev=edge-router'
        ),
    }

    # 2. Individual Parser Benchmarks
    print("\n[2] Individual Parser Execution Benchmarks:")
    print(f"{'Parser / Vendor':<28} | {'Throughput (EPS)':<18} | {'Latency (µs)':<14} | {'Status'}")
    print("-" * 75)

    parser_results = {}
    for name, (parser_inst, raw_sample) in test_samples.items():
        # Pre-wrap RawEvent to measure pure parse() compute time
        event_obj = RawEvent(raw_message=raw_sample)
        
        # Warmup
        for _ in range(500):
            parser_inst.parse(event_obj)

        start = time.perf_counter()
        for _ in range(iterations):
            res = parser_inst.parse(event_obj)
        elapsed = time.perf_counter() - start

        ops = iterations / max(0.00001, elapsed)
        lat_us = (elapsed / iterations) * 1_000_000
        try:
            parser_results[name] = {"ops": ops, "lat": lat_us, "status": res.status}
            print(f"{name:<28} | {ops:>14,.0f} EPS | {lat_us:>10.2f} µs | {res.status.upper()}", flush=True)
        except Exception as e:
            print(f"ERROR on line 127 for {name}! res type: {type(res)}, res value: {res}, exception: {e}")
            parser_results[name] = {"ops": ops, "lat": lat_us, "status": "ERROR"}

    # 3. Full End-to-End Pipeline Ingestion Benchmark
    print("\n[3] Full End-to-End Pipeline Ingestion (Ingest -> Detect -> Parse -> Normalize -> Provenance):", flush=True)
    engine = KosmoporosEngine()
    monitor = ThroughputMonitor(console_logging=False)
    
    e2e_iterations = 2000
    raw_event_sample = test_samples["Fortinet FortiGate (KV)"][1]

    # Warmup
    for _ in range(200):
        engine.parse(raw_payload=raw_event_sample)

    start = time.perf_counter()
    for _ in range(e2e_iterations):
        t0 = time.perf_counter()
        ir = engine.parse(raw_payload=raw_event_sample)
        lat_us = (time.perf_counter() - t0) * 1_000_000
        monitor.record_event(byte_size=len(raw_event_sample), latency_us=lat_us)
    total_pipeline_time = time.perf_counter() - start

    pipeline_eps = e2e_iterations / max(0.00001, total_pipeline_time)
    pipeline_lat_us = (total_pipeline_time / e2e_iterations) * 1_000_000
    mon_stats = monitor.get_stats()

    print(f"    E2E Ingestion Rate : {pipeline_eps:,.0f} logs/sec (EPS)", flush=True)
    print(f"    E2E Average Latency: {pipeline_lat_us:.2f} µs per event", flush=True)
    print(f"    Throughput Bandwidth: {mon_stats['throughput_mb_s']:.3f} MB/sec", flush=True)
    print(f"    Pipeline Result Status: {ir.status.upper()} (Canonical Formed)", flush=True)

    # 4. Multi-Core Async Queue Ingestion Benchmark
    import asyncio
    import os
    from app.collectors.queue import AsyncIngestionQueue
    from app.collectors.ingress import RawIngress

    print("\n[4] Hybrid Multi-Core Async Queue Benchmark (ProcessPoolExecutor):", flush=True)
    async def async_benchmark():
        cores = os.cpu_count() or 4
        print(f"    Initializing AsyncIngestionQueue with {cores} process workers...")
        
        loop = asyncio.get_running_loop()
        finished_future = loop.create_future()
        processed_count = 0
        total_async_iterations = e2e_iterations * 2

        def callback(event, source_name):
            nonlocal processed_count
            processed_count += 1
            if processed_count >= total_async_iterations and not finished_future.done():
                finished_future.set_result(True)

        async_queue = AsyncIngestionQueue(
            worker_count=cores,
            max_size=total_async_iterations + 100,
            max_eps=1_000_000,
            event_callback=callback
        )
        
        async_queue.start()
        
        # Give executor workers time to spawn
        await asyncio.sleep(1.0)
        
        print(f"    Dispatching {total_async_iterations:,} raw payloads asynchronously...")
        ingress_item = RawIngress(raw_text=raw_event_sample, source="benchmark", connector_type="http", transport_metadata={})
        
        start_time = time.perf_counter()
        
        for _ in range(total_async_iterations):
            async_queue.enqueue(ingress_item)
            
        await finished_future
        total_async_time = time.perf_counter() - start_time
        
        async_queue.stop()
        
        async_eps = total_async_iterations / max(0.00001, total_async_time)
        print(f"    Multi-Core Async Ingestion Rate : {async_eps:,.0f} logs/sec (EPS)", flush=True)
        print(f"    Time Elapsed : {total_async_time:.3f} s", flush=True)
        print(f"    Scaling Factor vs Sync : {async_eps / pipeline_eps:.2f}x", flush=True)

    try:
        asyncio.run(async_benchmark())
    except Exception as e:
        print(f"    Async benchmark failed: {e}")

    print("\n" + "=" * 80, flush=True)
    print("                      BENCHMARK COMPLETE", flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    run_benchmarks(iterations=5000)
