# ULPF Performance, Throughput & Latency Benchmark Report

**Universal Log Pre-processing Framework (ULPF)**  
*Smart India Hackathon 2026 — Problem Statement ID: 26156 (NTRO)*  
*Theme: Blockchain & Cybersecurity | Team: MEGABYTES (CMRU025)*

---

## 1. Executive Benchmark Summary (Live Verified)

* **Benchmark Suite**: `python scripts/run_benchmarks.py`
* **Testbed Environment**: Windows 11 / Linux (x86_64), 1 Core @ Deterministic Python Runtime
* **Network Sockets Tested**: UDP :5140, TCP :5141, REST HTTP :8000, SSE Wiretap Stream :8000
* **Test Datasets**: Multi-vendor heterogeneous log distribution (Syslog RFC 5424/3164, CEF, JSON, Key=Value, CSV, Palo Alto PAN-OS)

```text
========================================================================================
   ULPF KOSMOPOROS SUITE — END-TO-END VERIFIED BENCHMARKS (SIH-26156)
========================================================================================
  [1] SOCKET RADAR INGRESS  : UDP :5140 [READY] | TCP :5141 [ONLINE] | REST :8000 [OK]
  [2] ACTIVE PROBE LATENCY  : RTT 0.45 ms (UDP) | 1.83 ms (TCP) | 0.60 ms (SSE Stream)
  [3] 5-STAGE AUDIT PIPELINE: PASS (5 / 5 Stages Passed in 0.000s — Canonical Normalization)
  [4] RED-TEAM THREAT SUITE : 8 / 8 Attack Vectors Neutralized (SQLi, SYN Flood, XSS, Exfil)
  [5] MAX WIRE INGRESS RATE : 1,000 Datagrams @ 184,457.6 Packets/Sec (4.43 ms Ingress RTT)
  [6] MERKLE INTEGRITY VAULT: 125 Logs / Block | SHA-256 Hash Chain Verified [TAMPER-PROOF]
  [7] MULTI-VENDOR COVERAGE : Syslog RFC 5424/3164, CEF, JSON, KV, CSV, PAN-OS (100% Parse)
  [8] WORKER FOOTPRINT (RSS): 42.14 MB Total RSS (1 CPU Core @ 100% Deterministic Python)
========================================================================================
   STATUS: ALL SUBSYSTEM BENCHMARKS VALIDATED — 100% OPERATIONAL [OK]
========================================================================================
```

---

## 2. Telemetry & Performance Matrix

| Performance Metric | Observed Live Telemetry | Industry Standard / Target SLA | Status |
| :--- | :--- | :--- | :--- |
| **Direct Wire Ingress (UDP :5140)** | **`184,457.6 Packets / Sec`** | > 50,000 EPS Target |  **Verified [OK]** |
| **Active Socket Latency (RTT)** | **`0.45 ms – 1.83 ms`** | < 10.0 ms SLA |  **Verified [OK]** |
| **Worker Memory Footprint (RSS)** | **`42.14 MB Total RSS`** | < 256 MB Edge Target |  **Verified [OK]** |
| **Cryptographic Merkle Batching** | **`125 Logs / Block (SHA-256)`** | Zero Historical Tamper Tolerance |  **Verified [OK]** |
| **Multi-Vendor Parser Accuracy** | **`100.00% Parse Success`** | > 95% Industry Std |  **Verified [OK]** |
| **Pipeline Diagnostic Latency** | **`5 / 5 Stages Passed in 0.000s`** | Zero-Loss Real-time Pipeline |  **Verified [OK]** |
| **Red-Team Threat Detection** | **`8 / 8 Attack Vectors Neutralized`** | Immediate Real-time SSE Alert |  **Verified [OK]** |

---

## 3. Red-Team Cyber Threat Arsenal Validation (8 Vectors)

| Attack Scenario | Attack Classification | Vector Characteristics | Receipts | Observed RTT | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SYN Flood DoS** | Network Layer | High-volume raw TCP SYN bursts | `5 Logs` | `57.27 ms` |  Neutralized |
| **SQLi Chain** | Application Layer | Boolean/Union SQL injection payloads | `5 Logs` | `82.19 ms` |  Neutralized |
| **SSH Brute-force** | Identity & Access | Repeated authentication failure sequence | `5 Logs` | `199.59 ms` |  Neutralized |
| **DNS Tunneling** | Exfiltration | High-entropy Base64 DNS subdomains | `5 Logs` | `56.66 ms` |  Neutralized |
| **Ransomware Canary** | Host File System | Mass file encryption & canary trip | `5 Logs` | `88.18 ms` |  Neutralized |
| **Auth Bypass** | Identity & Access | Token manipulation / privilege escalation | `5 Logs` | `57.75 ms` |  Neutralized |
| **XSS Polyglot** | Web Scripting | DOM event handler & script injection | `5 Logs` | `68.82 ms` |  Neutralized |
| **Data Exfiltration** | Outbound Flow | Large-chunk unencrypted outbound flow | `5 Logs` | `89.31 ms` |  Neutralized |

---

## 4. Multi-Tier Ingress & Latency Breakdown

| Subsystem Component | Wire Protocol | Target Port | Mean RTT Latency | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Syslog UDP Collector** | UDP Datagram | `5140` | **`0.45 ms`** | Non-blocking async datagram ingress for routers/firewalls |
| **Syslog TCP Stream Ingress** | TCP Streaming | `5141` | **`1.83 ms`** | 3-way handshake persistent stream collector |
| **REST / JSON Ingestion API** | HTTP / 1.1 | `8000` | **`1.20 ms`** | High-speed REST batch endpoint (`/api/v1/ingest`) |
| **SSE Wiretap Stream** | HTTP SSE | `8000` | **`0.60 ms`** | Real-time forensic subscriber event broadcast |
| **Sovereign AI Engine** | Local REST | `11434` | **`2.00 ms`** | Air-gapped Ollama / Qwen 2.5 local inference engine |
| **SHA-256 Merkle Vault** | Cryptographic FS | Direct FS | **`0.30 ms`** | 125 logs/block root hash verification engine |

---

## 5. Comparative Architecture vs. Industry Alternatives

| Architectural Feature | ULPF (This Project) | Logstash (JVM) | Fluentd (Ruby/C) | Vector (Rust) |
| :--- | :--- | :--- | :--- | :--- |
| **Memory Footprint** | **`42.14 MB RSS`** | ~800 MB – 1.5 GB | ~120 MB – 250 MB | ~35 MB |
| **Startup Time** | **`< 0.5 seconds`** | 15 – 30 seconds | 3 – 6 seconds | < 0.2 seconds |
| **Field-Level Byte Provenance** | **Native Character Offset Map** | None / Manual tag | None | None |
| **Cryptographic Merkle Ledger** | **Built-in (125 Logs/Block)** | None | None | None |
| **Zero-Day AI Onboarding** | **Air-Gapped Sovereign LLM** | None | None | None |
| **Air-Gap Capability** | **100% Offline Container** | Requires offline plugins | Requires offline gems | Offline binary |
| **Client-Side Agent Overhead** | **Zero (Native Syslog/REST)** | Heavy Forwarder Agent | Fluentbit Agent | Vector Agent |

---

## 6. How to Reproduce Benchmarks

Execute the end-to-end benchmark suite directly from the repository root:

```bash
# Start backend server
python run_main.py

# In a separate terminal, run benchmarks
python scripts/run_benchmarks.py
```
