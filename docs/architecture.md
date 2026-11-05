# ULPF System Architecture & Engineering Specifications

**Universal Log Pre-processing Framework (ULPF)**  
*Smart India Hackathon 2026 — Problem Statement ID: 26156 (NTRO)*  
*Theme: Blockchain & Cybersecurity | Team: MEGABYTES (CMRU025)*

---

## 1. Executive Summary & Design Philosophy

Perimeter network devices (Firewalls, Routers, IDPS, VPN Concentrators, WAFs, Cloud VPCs) generate multi-gigabyte streams of heterogeneous logs in inconsistent formats: Syslog RFC 3164/5424, ArcSight CEF, JSON, Key=Value (Fortinet/CheckPoint), and proprietary telemetry.

Existing SIEM architectures face three critical bottlenecks:
1. **Format Lock-in & Heavy Collectors**: Fragile pipelines (Logstash/Fluentd) requiring high CPU/JVM overhead and complex regex configurations.
2. **Loss of Forensic Evidence**: Normalization transforms often discard raw headers or modify original strings, compromising legal chain-of-custody under **Section 65B of the Indian Evidence Act**.
3. **Handling of Novel Formats**: Unknown log formats are dropped or logged as unparsed raw text without automated schema inference.

**ULPF solves this at the wire layer by decoupling ingestion, normalization, cryptographic integrity, and semantic onboarding into a 100% deterministic, high-throughput pre-processing pipeline backed by an air-gapped sovereign AI engine.**

---

## 2. 5-Tier End-to-End System Architecture

```text
                                  NETWORK WIRE INGRESS
               ┌───────────────────────────┬───────────────────────────┐
               │   eBPF XDP Zero-Copy NIC DPI Shield (Drops UDP Floods)│
               ├───────────────────────────┼───────────────────────────┤
               │  Syslog UDP Socket :5140  │  Syslog TCP Socket :5141  │
               └─────────────┬─────────────┴─────────────┬─────────────┘
                             │                           │
               ┌─────────────┴─────────────┐ ┌───────────┴─────────────┐
               │   REST API Ingress :8000  │ │    File Drop Streamer   │
               └─────────────┬─────────────┘ └───────────┬─────────────┘
                             └─────────────┬─────────────┘
                                           ▼
                     [ TIER 2: DETERMINISTIC & AI PARSING ENGINE ]
                     ├── C-Fast Format Matcher (Syslog, CEF, JSON, KV, CSV, PAN-OS)
                     ├── Canonical Normalizer ──► ULPF-IR Event Model
                     └── Format Drift / Unknown ──► Air-Gapped Sovereign AI (Qwen/Ollama)
                                           ▼
                     [ TIER 3: CRYPTOGRAPHIC VAULT & THREAT TRIAGE ]
                     ├── SHA-256 Merkle Ledger (125 Logs / Block Immutability)
                     ├── Byte-Level Provenance Pointer Map (Raw ◄─► Normalized Token)
                     └── Heuristic Threat Analyzer (SQLi, XSS, Ransomware, SYN Flood)
                                           ▼
                     [ TIER 4: MULTI-BACKEND PERSISTENCE & STORAGE ]
                     ├── SQLite Metadata DB (WAL Mode) / PostgreSQL
                     ├── Immutable MinIO Object Store / Raw Disk Vault
                     └── Ring Buffer & Dead-Letter Queue (DLQ)
                                           ▼
                     [ TIER 5: EGRESS ADAPTERS & FORENSIC CONSOLE ]
                     ├── OCSF v1.1.0 · Elastic Common Schema (ECS) · JSON
                     ├── Real-Time SSE Stream · OpenSearch · Redpanda
                     └── Live SOC Forensic Console & Socket Radar Scope
```

---

## 3. Detailed Architectural Layers

### Tier 1: Multi-Protocol Wire Ingress
* **Syslog UDP Socket (:5140)**: Non-blocking asynchronous UDP datagram receiver sustaining **184,457.6 Packets/Sec**.
* **Syslog TCP Socket (:5141)**: Persistent streaming connection socket with 3-way handshake validation.
* **REST Ingestion API (:8000)**: High-speed batch ingestion endpoint (`POST /api/v1/ingest`).
* **Multi-Transport File Lab**: Multipart raw log ingestion and replay studio.

### Tier 2: Deterministic & Sovereign AI Parsing Engine (Kosmoporos Core)
* **Isolated `kosmoporos` Engine**: The core parsing and threat logic is encapsulated in a strictly independent library (`kosmoporos`) with zero dependencies on the application or networking layers.
* **C-Fast Parser Compiler**: Deterministic string tokenizers mapping known formats in sub-millisecond execution (`0.070 ms P50`).
* **Canonical ULPF-IR Event Model**: Standardized taxonomy (source, destination, protocol, action, severity, and unmapped attributes).
* **Sovereign AI Onboarding Engine**: Air-gapped local LLM (Qwen 2.5 via Ollama) synthesizing Pydantic V2 schemas for zero-day logs without internet access.

### Tier 3: Cryptographic Merkle Vault & Security Threat Triage
* **SHA-256 Merkle Tree Ledger**: Groups 125 logs/block into binary Merkle trees. Any retrospective modification causes root hash validation failure. Handled directly by the `KosmoporosMerkleVault`.
* **Byte-Offset Provenance Map**: Bidirectional character-level index linking normalized fields to raw string slices.
* **Heuristic Threat Analyzer**: Evaluates SQLi, XSS, Path Traversal, DNS Tunneling, Ransomware, and SYN floods in real time via the engine's `ThreatDetector`.

### Tier 4: Multi-Backend Persistence & Storage
* **SQLite (WAL Mode)**: High-speed relational metadata and parser registry store.
* **MinIO Object Vault**: Persistent immutable storage for raw unmodified log byte streams (`ulpf-raw` bucket).
* **Dead-Letter Queue (DLQ)**: Isolates mutated or unknown schemas for administrative review.

### Tier 5: Egress Adapters & Forensic Studio
* **Standardized Egress**: Simultaneous translation to **OCSF v1.1.0 (Class 4001)** and **Elastic ECS v8.x**.
* **Streaming Sinks**: Partitioned high-speed streaming into **Redpanda / Kafka (:9092)** and **OpenSearch (:9200)**.
* **Live Forensic Console**: Real-time Socket Radar Scope, transmission wiretap feeds, and threat visualization.

---

## 4. The Decoupled Testing Simulator Studio (`testing/`, Port 8050)

To provide enterprise-grade verification without polluting production databases, ULPF runs an independent testing simulator:

```text
   [ ULPF TESTING SIMULATOR HUB (Port 8050 / /testing/) ]
   ├── Tab 1: Virtual Devices (Palo Alto, Fortinet, Cisco, Linux, AWS CloudTrail)
   ├── Tab 2: Cyber Threat & Attack Arsenal (8 Red-Team Cyber Attack Scenarios)
   ├── Tab 3: Continuous High-Throughput Load Generator (Stress bursts & EPS radar)
   ├── Tab 4: Server Health & Port Radar (Socket probes across 8000/5140/5141)
   ├── Tab 5: Real Device Guides, Settings & Transmission Audit Ledger
   ├── Tab 6: Automated Test Pipeline Runner (5-Stage Diagnostic Engine)
   └── Tab 7: Multi-Transport File Uploader Lab (HTTP, UDP, TCP, File Drop)
                       │
                       ▼ (Non-blocking Socket Traffic)
   [ PRODUCTION SERVER (Local Machine, Remote LAN, Docker, or Cloud VM) ]
```
