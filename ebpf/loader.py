# ebpf/loader.py
# -----------------------------------------------------------------------------
# ULPF eBPF XDP Loader & Metrics Monitor
# -----------------------------------------------------------------------------
# Loads the compiled XDP C program into the Linux Kernel using BCC.
# Streams live metrics (Passed vs Dropped) from the Kernel Map.
# -----------------------------------------------------------------------------

from bcc import BPF
import time
import ctypes

device = "eth0" # Switch to 'ens3' or 'lo' depending on environment

print(f"[*] Compiling eBPF program and attaching to {device}...")

try:
    b = BPF(src_file="xdp_filter.c")
    fn = b.load_func("xdp_drop_noise", BPF.XDP)
    b.attach_xdp(device, fn, 0)
except Exception as e:
    print(f"[!] Critical Error loading eBPF: {e}")
    print("[!] Ensure you are running on Linux as Root with BCC installed.")
    exit(1)

print(f"[*] Successfully attached eBPF XDP program to {device}.")
print("[*] Shield active. Monitoring traffic on port 5140...")

stats_map = b.get_table("xdp_stats_map")

def get_metric(index):
    try:
        # Array maps are per-cpu, need to sum across CPUs
        values = stats_map.getValue(index)
        return sum(v.value for v in values)
    except:
        return 0

import json
import os

metrics_file = "ebpf_metrics.json"

try:
    while True:
        time.sleep(2)
        passed = get_metric(0)
        dropped = get_metric(1)
        print(f"[Kernel Metrics] Valid Logs Passed: {passed} | Garbage Packets Dropped: {dropped}")
        
        # Write to state file for dashboard
        with open(metrics_file, "w") as f:
            json.dump({"passed": passed, "dropped": dropped, "timestamp": time.time()}, f)
            
except KeyboardInterrupt:
    print("\n[*] Detaching eBPF program and restoring OS networking...")
    b.remove_xdp(device, 0)
    print("[*] Done.")
