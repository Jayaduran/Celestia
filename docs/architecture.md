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
* **Island Zen Garden Sovereign Ingress**: Minimalist, zen-garden landing page (`/` and `/landing/`) styled in warm earthy tones (`#EDE9E6`, `#C9996B`, `#5C4F4A`, `#5C766D`) acting as the public portal with operator sign-in modal before forwarding to the SOC Forensic Console.

---

## 4. Operator Authentication & Telephony Presence Shield

To safeguard enterprise SOC operations from both unauthorized tampering and notification fatigue, ULPF introduces a real-time operator presence and credential subsystem:

```text
       ┌────────────────────────────────────────────────────────┐
       │             Browser Visitor / SOC Operator             │
       └───────────────────────────┬────────────────────────────┘
                                   │
              10s Presence Beacon  │ (POST /api/v1/auth/heartbeat)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │        Operator Auth & Presence Shield (app/auth)      │
       │  • SQLite WAL Session & Operator Table (Salted SHA-256)│
       │  • Sliding 45s Activity Window Tracked In-Memory       │
       └───────────────────────────┬────────────────────────────┘
                                   │
                      Active Presence Detected?
                      ├── YES ──► Suppress Voice Call (Operator Monitoring Web)
                      │
                      └── NO  ──► Is Threat Critical & Validated Attack?
                                   ├── YES ──► Autonomous Twilio Voice Call (TwiML)
                                   └── NO  ──► Suppress (Benign RFC 5424 PRI 2 / Block Drop)
```

### 4.1 Operator Credentials & Session Management
- **Local SQLite Database (`data/auth.db`)**: Isolated WAL-mode database storing registered security operators and active bearer tokens.
- **Salted SHA-256 Hashing**: 16-byte cryptographically secure random salt paired with SHA-256 prevents rainbow table and collision exploits.
- **Session Tokens**: 32-byte cryptographic hex tokens validated on protected routes with sliding expiration (configurable via `AUTH_SESSION_EXPIRY_HOURS`).

### 4.2 Web Presence Shield
- **10-Second Heartbeats**: Both unauthenticated visitors on the landing page and authenticated operators in the SOC console emit periodic heartbeats (`POST /api/v1/auth/heartbeat`).
- **45-Second Sliding Window**: If any active web session has checked in within the last 45 seconds (`AUTH_PRESENCE_TIMEOUT_SECONDS`), operator presence is marked **ACTIVE**.
- **Alert Suppression**: Automated phone notifications are silenced while human eyes are actively viewing the screen, preventing notification spam.

---

## 5. Autonomous Twilio Voice Telephony Dispatch

When perimeter defenses detect a verified critical cyberattack while **no operator is on the web**, ULPF automatically dials the designated security officer via carrier voice lines:

* **Strict Threat Qualification**:
  Routine syslogs with RFC 5424 PRI 2 (severity code 2 = "Critical") or routine blacklisted IP discards are intentionally **excluded** from triggering voice calls. Telephony dispatch strictly requires a verified cyberattack signature (SQLi, XSS, Ransomware, Brute-Force, etc.) with `severity == "critical"`.
* **Dynamic TwiML Generation**: Synthesizes neural text-to-speech alerting the responder with the specific threat classification, source IP, and timestamp:
  ```xml
  <Response>
    <Say voice="Polly.Joanna-Neural">
      Emergency Security Alert from Celestia ULPF. A critical threat has been detected: SQL Injection Exploit from IP 198.51.100.44. Please inspect the SOC console immediately.
    </Say>
  </Response>
  ```
* **Cooldown Deduplication Guard**: Enforces an atomic 60-second cooldown (`TWILIO_COOLDOWN_SECONDS`) to prevent concurrent storm calls during distributed flood events.
* **Carrier Mocking in Test**: Seamlessly mocked in unit testing (`_dispatch_carrier_call`) ensuring zero carrier charges during automated CI/CD runs.

---

## 6. The Decoupled Testing Simulator Studio (`testing/`, Port 8050)

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
