#!/usr/bin/env python3
"""
ULPF Network Source Simulator (CLI Syslog Ingress Client)
Simulates realistic enterprise perimeter devices (Firewall, Router, VPN, IDS, Auth)
transmitting RFC 3164/5424 UDP and TCP Syslog datagrams to the ULPF ingestion gateway.
"""

import sys
import time
import socket
import argparse
import random
from datetime import datetime, timezone

# Multi-vendor realistic test templates
SIMULATED_LOG_TEMPLATES = [
    # 1. Fortinet FortiGate CEF Firewall Log
    {
        "vendor": "fortinet",
        "format": "cef",
        "template": 'CEF:0|Fortinet|FortiGate|7.2.4|32001|traffic:allow|3|src={src_ip} dst={dst_ip} spt={sport} dpt={dport} proto=tcp act={action} devname="FGT-EDGE-01" msg="[SIMULATED NETWORK DEVICE] Ingress firewall policy match"',
    },
    # 2. Cisco ASA Syslog Router/Firewall Log
    {
        "vendor": "cisco",
        "format": "syslog",
        "template": '<134>{timestamp} ciscoasa: %ASA-4-106023: {action_cisco} tcp src outside:{src_ip}/{sport} dst inside:{dst_ip}/{dport} by access-group "PERIMETER_SEC" [0x0, 0x0] [SIMULATED NETWORK DEVICE]',
    },
    # 3. Palo Alto Networks NGFW Key=Value Log
    {
        "vendor": "paloalto",
        "format": "kv",
        "template": 'devname="PA-5220-DC" type="TRAFFIC" subtype="end" srcip={src_ip} dstip={dst_ip} srcport={sport} dstport={dport} proto=6 action="{action}" rule="ALLOW_SECURE_WEB" msg="[SIMULATED NETWORK DEVICE] Session closed"',
    },
    # 4. Suricata IDS LEEF Alert
    {
        "vendor": "suricata",
        "format": "leef",
        "template": 'LEEF:2.0|Suricata|Suricata-IDS|6.0.8|ALERT|devTime={timestamp_iso}|src={src_ip}|dst={dst_ip}|spt={sport}|dpt={dport}|proto=TCP|cat=NetworkSecurity|act={action}|sev=4|msg="[SIMULATED NETWORK DEVICE] ET SCAN Potential SSH Brute Force Attempt"',
    },
    # 5. Linux Auth Server Syslog
    {
        "vendor": "linux",
        "format": "syslog",
        "template": '<86>{timestamp} auth-server-01 sshd[28412]: Accepted publickey for admin from {src_ip} port {sport} ssh2: RSA SHA256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a [SIMULATED NETWORK DEVICE]',
    },
    # 6. Cloud WAF JSON Access Event
    {
        "vendor": "waf",
        "format": "json",
        "template": '{{"agent": "Perimeter-WAF-01", "client_ip": "{src_ip}", "dest_ip": "{dst_ip}", "dest_port": {dport}, "method": "POST", "uri": "/api/v1/auth", "status": {status_code}, "action": "{action}", "msg": "[SIMULATED NETWORK DEVICE] TLS API Traffic Inspection"}}',
    },
]


def generate_simulated_log(vendor: str = "all", format_type: str = "auto") -> str:
    """Generate realistic synthetic log payload for a given vendor / format."""
    candidates = SIMULATED_LOG_TEMPLATES
    if vendor != "all":
        candidates = [c for c in candidates if c["vendor"].lower() == vendor.lower()] or candidates
    if format_type != "auto":
        candidates = [c for c in candidates if c["format"].lower() == format_type.lower()] or candidates

    chosen = random.choice(candidates)

    src_ip = f"10.{random.randint(0, 10)}.{random.randint(1, 250)}.{random.randint(2, 250)}"
    dst_ip = f"192.168.{random.randint(1, 10)}.{random.randint(2, 100)}"
    sport = random.randint(30000, 65000)
    dport = random.choice([80, 443, 22, 53, 8080, 8443, 3389])
    action = random.choice(["allow", "deny", "drop", "allow", "allow"])
    action_cisco = "Deny" if action in ("deny", "drop") else "Permit"
    status_code = 200 if action == "allow" else 403

    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%b %d %H:%M:%S")
    ts_iso = now.isoformat()

    return chosen["template"].format(
        src_ip=src_ip,
        dst_ip=dst_ip,
        sport=sport,
        dport=dport,
        action=action,
        action_cisco=action_cisco,
        status_code=status_code,
        timestamp=ts_str,
        timestamp_iso=ts_iso,
    )


def send_udp(host: str, port: int, count: int, rate: int, vendor: str, format_type: str):
    """Transmit logs via UDP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f" Sending {count} UDP Syslog datagrams to {host}:{port} (Rate: {rate if rate > 0 else 'MAX'} EPS)...")

    delay = 1.0 / rate if rate > 0 else 0
    t0 = time.time()
    bytes_sent = 0

    for i in range(count):
        log_msg = generate_simulated_log(vendor=vendor, format_type=format_type)
        payload = log_msg.encode("utf-8")
        sock.sendto(payload, (host, port))
        bytes_sent += len(payload)

        if delay > 0:
            time.sleep(delay)

    elapsed = max(time.time() - t0, 0.001)
    achieved_eps = round(count / elapsed, 2)
    print(f" Transmitted {count} UDP packets ({bytes_sent:,} bytes) in {elapsed:.3f}s -> {achieved_eps:,} EPS achieved.")
    sock.close()


def send_tcp(host: str, port: int, count: int, rate: int, vendor: str, format_type: str):
    """Transmit logs via persistent TCP connection."""
    print(f" Connecting to TCP Syslog server at {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except Exception as e:
        print(f" Failed to connect to TCP Syslog server {host}:{port}: {e}")
        sys.exit(1)

    print(f"   Connected! Sending {count} framed TCP log messages...")
    delay = 1.0 / rate if rate > 0 else 0
    t0 = time.time()
    bytes_sent = 0

    for i in range(count):
        log_msg = generate_simulated_log(vendor=vendor, format_type=format_type)
        payload = (log_msg + "\n").encode("utf-8")
        sock.sendall(payload)
        bytes_sent += len(payload)

        if delay > 0:
            time.sleep(delay)

    elapsed = max(time.time() - t0, 0.001)
    achieved_eps = round(count / elapsed, 2)
    print(f" Transmitted {count} TCP messages ({bytes_sent:,} bytes) in {elapsed:.3f}s -> {achieved_eps:,} EPS achieved.")
    sock.close()


def main():
    parser = argparse.ArgumentParser(description="ULPF Real Network Log & Syslog Traffic Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="Target ULPF collector host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Target collector port (default: 5140 for UDP, 5141 for TCP)")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Transport protocol (udp/tcp)")
    parser.add_argument("--count", type=int, default=10, help="Number of log messages to generate and send")
    parser.add_argument("--rate", type=int, default=0, help="Target rate limit in Events/Sec (0 = maximum speed)")
    parser.add_argument("--vendor", default="all", choices=["all", "fortinet", "cisco", "paloalto", "suricata", "linux", "waf"], help="Vendor log profile")
    parser.add_argument("--format", default="auto", choices=["auto", "cef", "syslog", "json", "kv", "leef"], help="Format profile")

    args = parser.parse_args()

    port = args.port
    if port is None:
        port = 5140 if args.protocol == "udp" else 5141

    print("=" * 70)
    print("   ULPF NETWORK LOG SIMULATOR (SIMULATED NETWORK DEVICE INGRESS)")
    print("=" * 70)

    if args.protocol == "udp":
        send_udp(args.host, port, args.count, args.rate, args.vendor, args.format)
    else:
        send_tcp(args.host, port, args.count, args.rate, args.vendor, args.format)

    print("=" * 70)


if __name__ == "__main__":
    main()
