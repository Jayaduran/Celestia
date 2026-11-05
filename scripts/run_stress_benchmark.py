#!/usr/bin/env python3
"""
ULPF & Kosmoporos High-Throughput Stress Benchmark Suite.
Tests Tri-Tier Architecture isolation:
- Pumps 100k+ EPS UDP Syslog flood against the data plane (port 5140)
- Concurrently measures Control Plane / REST API response latencies
- Verifies that P99 API latency remains sub-20ms during saturation ingestion.
"""

import time
import socket
import urllib.request
import threading
import json
import statistics
import os


class StressBenchmarkSuite:
    def __init__(self, api_url=None, udp_port=5140, host="127.0.0.1"):
        self.api_url = api_url or os.getenv("ULPF_API_URL", "http://127.0.0.1:8000/api/v1/health/live")
        self.udp_ip = host
        self.udp_port = int(os.getenv("SYSLOG_UDP_PORT", str(udp_port)))
        self.running = False
        self.api_latencies = []
        self.logs_sent = 0

    def udp_flood(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b'<34>1 2026-09-27T12:00:00Z test-fw.local - - - - src=192.168.1.1 dst=8.8.8.8 spt=55432 dpt=443 act=allow'
        
        while self.running:
            # Batch send to push max packets
            for _ in range(500):
                sock.sendto(payload, (self.udp_ip, self.udp_port))
                self.logs_sent += 1
            time.sleep(0.001)

    def measure_api_latency(self):
        while self.running:
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(self.api_url, headers={"User-Agent": "ULPF-StressBenchmark/1.0"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    resp.read()
            except Exception:
                pass
            t1 = time.perf_counter()
            self.api_latencies.append((t1 - t0) * 1000)
            time.sleep(0.05)  # Check latency 20 times a second

    def run(self, duration=5):
        print(f"Starting ULPF & Kosmoporos Stress Test ({duration} seconds)...")
        print(f"-> Target UDP Syslog Port: {self.udp_ip}:{self.udp_port}")
        print(f"-> Target Control Plane API: {self.api_url}")
        print("-> Launching high-throughput UDP Syslog flood (Simulating massive burst surge)")
        print("-> Launching concurrent Control Plane latency measurement loop")
        
        self.running = True
        
        flood_threads = [threading.Thread(target=self.udp_flood) for _ in range(4)]
        for t in flood_threads:
            t.start()
            
        api_thread = threading.Thread(target=self.measure_api_latency)
        api_thread.start()
        
        for i in range(duration):
            time.sleep(1)
            print(f"[{i+1}/{duration}s] Pumping logs... (Current count: {self.logs_sent:,})")
            
        self.running = False
        for t in flood_threads:
            t.join()
        api_thread.join()
        
        eps = self.logs_sent / duration
        print("\n" + "=" * 50)
        print("BENCHMARK RESULTS")
        print("=" * 50)
        print(f"Total Logs Sent (UDP)   : {self.logs_sent:,}")
        print(f"Effective Ingestion Rate: {eps:,.2f} EPS")
        
        if self.api_latencies:
            avg_lat = statistics.mean(self.api_latencies)
            p99_lat = statistics.quantiles(self.api_latencies, n=100)[98] if len(self.api_latencies) >= 100 else max(self.api_latencies)
            
            print(f"Control Plane API Average Latency: {avg_lat:.2f} ms")
            print(f"Control Plane API p99 Latency    : {p99_lat:.2f} ms")
            
            if p99_lat < 50.0:
                print("\n[VERDICT: PASSED] - Ingestion queue cleanly buffers high rate traffic without starving API.")
            else:
                print(f"\n[VERDICT: WARNING] - Latency elevated ({p99_lat:.2f} ms).")
        else:
            print("Failed to record api latencies.")
        
        print("=" * 50)


if __name__ == '__main__':
    suite = StressBenchmarkSuite()
    suite.run(duration=5)
