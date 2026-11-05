# ULPF Ingestion Architecture & Log Storage Guide

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

---

## 1. Overview & Transport Matrix

ULPF serves as a high-performance preprocessing gateway between heterogeneous enterprise network devices and downstream SIEM/analytics systems:

```
Firewall / Router / VPN / IDS / Workstation / Server
                        │
       ┌────────────────┼────────────────┬────────────────┐
       ▼                ▼                ▼                ▼
Syslog UDP (:5140)  Syslog TCP (:5141)  HTTP REST (:8000)  File Drop (storage/logs/)
       │                │                │                │
       └────────────────┼────────────────┴────────────────┘
                        │
                        ▼
             [ Ingestion Rate Limiter ]
                        │
                        ▼
             [ 1. Raw Integrity Seal ]
             ├── Calculate SHA-256 Digest
             ├── Assign UUID / Event ID
             └── Write to Immutable Raw Storage (storage/raw/)
                        │
                        ▼
             [ 2. Four-Tier Format Detector ]
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
Known Format (Confidence ≥ 0.70)   Unknown Format (Confidence < 0.70)
         │                             │
         ▼                             ▼
[ Deterministic Parsers ]      [ Unknown Quarantine & AI Onboarding ]
(CEF, Syslog, JSON, LEEF, KV)  (storage/ulpf_unknown.db & Local SLM)
         │                             │
         └──────────────┬──────────────┘
                        │
                        ▼
          [ Semantic Normalization to ULPF-IR ]
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
SQLite Event Ledger   OpenSearch     MinIO S3
(storage/ulpf_events.db)  (:9200)      (:9000)
```

---

## 2. Ingress Network Collectors

### 2.1 Syslog UDP Collector (Port `5140`)
* **Protocols**: RFC 3164 (BSD Syslog) and RFC 5424 (IETF Structured Syslog).
* **Interface**: Listens on `0.0.0.0:5140` for UDP datagrams.
* **Resilience**: Non-blocking asynchronous socket with `select.select()` and non-crashing `errors="replace"` UTF-8 decoding. Handles packets up to 65,535 bytes.
* **Integrity**: Immediate SHA-256 evidence hashing before any parsing occurs.

### 2.2 Syslog TCP Collector (Port `5141`)
* **Protocols**: RFC 5424 persistent TCP streams, newline-delimited (`\n`) and octet-counting framing.
* **Interface**: Listens on `0.0.0.0:5141` for persistent multi-client TCP connections.
* **Resilience**: Independent per-client thread buffer handling fragmented packets across multiple `recv()` calls.

### 2.3 HTTP REST Ingest Gateway (Port `8000`)
* **Endpoints**:
  * `POST /api/v1/ingest`: JSON payload containing `raw_log` and `source_id`.
  * `POST /api/v1/upload`: Multipart batch file ingestion for `.log`, `.txt`, `.raw`, `.json`, `.csv`, `.cef`, `.syslog`.

### 2.4 Watched Directory Collector (`storage/logs/`)
* **Service**: Automated filesystem watchdog monitoring `storage/logs/`.
* **Behavior**: Detects new log files dropped into the directory, streams them line-by-line through the normalization pipeline, computes cryptographic evidence, and archives the file.

---

## 3. Where Does the Server Store Received Logs? (Raw and Parsed)

ULPF maintains strict segregation between **immutable raw forensic evidence** and **normalized structured events**:

```
ulpf/
├── storage/
│       ├── raw/                       # 1. Immutable Raw Log Evidence Store
│       │   ├── ULPF-2026-1001.raw
│       │   └── ULPF-2026-1002.raw
│       ├── logs/                      # 2. Watched Directory for Log Drops
│       ├── ulpf_events.db             # 3. Normalized Canonical Events (SQLite)
│       └── ulpf_unknown.db            # 4. Quarantine Queue for Unknown Logs
```

### 3.1 Raw Logs Storage (`storage/raw/`)
* **Location**: `storage/raw/` on the server filesystem.
* **Format**: Individual raw bitstream files named by timestamp or assigned event ID:  
  `storage/raw/ULPF-YYYYMMDD-HHMMSS-<id>.raw`
* **Integrity Guarantee**:
  - Raw strings are **never modified, truncated, trimmed, or re-encoded**.
  - A cryptographic **SHA-256 digest** is computed directly across the raw bytes immediately upon socket ingress.
  - In distributed deployments, the raw bitstream is also pushed to the immutable **MinIO S3 bucket** (`ulpf-raw-evidence`) with write-once-read-many (WORM) retention policies.
  - Guarantees court-admissible chain of custody for digital forensics and compliance audits.

### 3.2 Parsed Logs Storage (`storage/ulpf_events.db` & OpenSearch)
* **Relational Storage**: SQLite database at `storage/ulpf_events.db`.
  - Stored in the `events` table with normalized columns: `event_id`, `timestamp`, `category`, `action`, `severity`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `vendor`, `product`, `raw_sha256`, and complete ULPF-IR JSON.
* **Search & Analytics**: OpenSearch cluster (`http://localhost:9200`, index `ulpf-events-v1`).
  - Indexed with high-performance schemas supporting free-text search, geo-ip enrichment, and security analytics visualizations in OpenSearch Dashboards (port 5601).

### 3.3 Unknown Logs Quarantine (`storage/ulpf_unknown.db`)
* **Location**: `storage/ulpf_unknown.db` (or `unknown_logs` table).
* **Contents**: Raw payload, ingress timestamp, source IP/port, confidence score (<0.70), failure reason, assigned SHA-256 seal, and current status (`PENDING_REVIEW`, `AI_SYNTHESIZED`, `APPROVED`).

---

## 4. How Logs Get Categorized as "Unknown"

When a raw log string enters the ULPF pipeline, it passes through a **4-stage deterministic decision cascade**:

```
[ Incoming Raw Log ]
        │
        ▼
[ Phase 1: Magic Header & Signature Check ]
├── Checks for CEF header ("CEF:0|") ──> CEF Parser (0.99)
├── Checks for LEEF header ("LEEF:1.0|") ──> LEEF Parser (0.99)
├── Checks for Syslog PRI ("<134>1 " or "<34>Oct") ──> Syslog Parser (0.95)
└── Checks for valid JSON ("{ ... }") ──> JSON Parser (1.00)
        │ (No signature matched)
        ▼
[ Phase 2: Key=Value & Delimiter Tokenizer ]
├── Evaluates field=value pairs (e.g. src=... dst=... action=...)
└── Computes token density ratio
        │ (Token density < 0.70 or irregular delimiters)
        ▼
[ Phase 3: Schema Validation & Required Fields ]
├── Requires valid Timestamp
├── Requires Event Identifier or Action
└── If mandatory fields cannot be extracted ──> Validation Fails
        │
        ▼
[ Phase 4: Quarantine Fallback ]
├── Confidence Score < 0.70
├── Format Tag: "unknown"
├── Preserves raw bitstream & computes SHA-256 evidence hash
└── Dispatches to Unknown Quarantine (storage/ulpf_unknown.db)
        │
        ▼
[ AI Onboarding Engine & Human Review Queue ]
```

### Why Logs Become "Unknown":
1. **Proprietary / Custom Vendor Formats**: Industrial SCADA systems, legacy mainframe applications, or in-house microservices that do not adhere to RFC standards.
2. **Corrupted or Truncated Frames**: Packets truncated at MTU boundaries or malformed during transmission.
3. **Obfuscated or Malicious Payloads**: Exploits designed to bypass WAF or IDS regular expressions by manipulating delimiters.
4. **Missing Timestamps**: Logs lacking valid ISO 8601 or BSD timestamps that fail chronological indexing requirements.

---

## 5. Multi-Transport File Upload Lab

The Testing Hub (`http://localhost:8050`, Tab 7) provides a dedicated file ingestion lab:

### 5.1 Supported Formats
* **File Types**: `.log`, `.txt`, `.raw`, `.json`, `.csv`, `.xml`, `.cef`, `.leef`, `.syslog` (up to 10 MB).
* **Pre-flight Recognition**: Automatically detects format signatures before transmission.
* **Interactive Editor**: Allows live editing, line counting, and byte size verification.

### 5.2 Four Ingestion Transport Modes:
1. **Direct HTTP REST Upload** (`POST /api/v1/upload`): Multipart file upload directly to ULPF Core with end-to-end normalization, SQLite storage, OpenSearch indexing, and sample parsed event cards.
2. **Sequential UDP Syslog Stream** (Port `5140`): Replays log lines as UDP datagrams with adjustable pacing delay (0–200 ms).
3. **Persistent TCP Syslog Stream** (Port `5141`): Streams log lines over persistent TCP framing.
4. **File Collector Drop** (`storage/logs/`): Simulates log rotation and automated file watching.

---

## 6. Connecting from Other Devices & Remote Machines

To allow other computers, firewalls, or cloud VMs to send logs to your ULPF server:

### 6.1 Server Host Configuration
1. **Bind Address**: ULPF collectors bind to `0.0.0.0` (all network interfaces), ensuring they accept traffic from localhost, local LAN, Docker networks, and external VPNs.
2. **Find Server LAN IP**:
   * Windows: `ipconfig` (e.g. `192.168.1.50`)
   * Linux: `ip a` or `hostname -I`

### 6.2 Firewall Ingress Rules
Ensure the operating system firewall permits inbound traffic on ULPF ingress ports:

* **Windows PowerShell (Run as Administrator)**:
```powershell
New-NetFirewallRule -DisplayName "ULPF HTTP API (8000)" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
New-NetFirewallRule -DisplayName "ULPF Testing Hub (8050)" -Direction Inbound -Protocol TCP -LocalPort 8050 -Action Allow
New-NetFirewallRule -DisplayName "ULPF Syslog UDP (5140)" -Direction Inbound -Protocol UDP -LocalPort 5140 -Action Allow
New-NetFirewallRule -DisplayName "ULPF Syslog TCP (5141)" -Direction Inbound -Protocol TCP -LocalPort 5141 -Action Allow
```

* **Linux (UFW)**:
```bash
sudo ufw allow 8000/tcp comment "ULPF HTTP API & Dashboard"
sudo ufw allow 8050/tcp comment "ULPF Testing Simulator Hub"
sudo ufw allow 5140/udp comment "ULPF Syslog UDP"
sudo ufw allow 5141/tcp comment "ULPF Syslog TCP"
```

### 6.3 Forwarding Configuration on Remote Devices
* **Linux (`rsyslog.conf`)**:
  ```ini
  *.* @192.168.1.50:5140;RSYSLOG_SyslogProtocol23Format
  ```
* **Cisco ASA / IOS**:
  ```cisco
  logging host inside 192.168.1.50 transport udp port 5140
  ```
* **Fortinet FortiGate**:
  ```fortios
  config log syslogd setting
      set status enable
      set server "192.168.1.50"
      set mode udp
      set port 5140
  end
  ```
* **HTTP cURL**:
  ```bash
  curl -X POST "http://192.168.1.50:8000/api/v1/ingest" \
    -H "Content-Type: application/json" \
    -d '{"raw_log": "CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1", "source_id": "Remote-Host"}'
  ```
