# ULPF REST API & Testing Hub Specification

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

---

##  Base URLs & Port Architecture

ULPF implements a clean separation between the **Core Production Server** and the **Testing Simulator Hub**:

| Service | Host & Port | Description |
| :--- | :--- | :--- |
| **Main Core Server & Dashboard** | `http://127.0.0.1:8000` | FastAPI gateway, semantic normalizer, SQLite event ledger, OpenSearch indexer, and web dashboard (`/dashboard`). |
| **Testing Simulator & Web Hub** | `http://127.0.0.1:8050` | Dedicated testing workbench, virtual devices, cyber attack arsenal, load generator, and test pipeline runner. |
| **Syslog UDP Collector** | `0.0.0.0:5140` | RFC 3164 / RFC 5424 high-speed stateless UDP syslog ingress. |
| **Syslog TCP Collector** | `0.0.0.0:5141` | RFC 5424 / octet-counting persistent streaming TCP syslog ingress. |

* Interactive OpenAPI / Swagger UI: `http://127.0.0.1:8000/docs`
* Testing Hub Swagger UI: `http://127.0.0.1:8050/docs`

---

## Part 1: Main Core Server API (`:8000`)

### 1. System Health & Diagnostics

#### `GET /api/v1/health/live`
Fast lightweight liveness probe. Returns HTTP 200 when the FastAPI worker is running.

**Response `200 OK`**:
```json
{
  "status": "online",
  "service": "ULPF Core Ingestion Gateway",
  "version": "1.0.0-SIH26156",
  "timestamp": "2026-09-09T01:30:00.000Z"
}
```

#### `GET /api/v1/system/readiness`
Deep readiness check verifying that all 7 internal subsystems are fully initialized and ready.

**Response `200 OK`**:
```json
{
  "status": "ready",
  "readiness_score": 100,
  "subsystems": {
    "api_gateway": { "status": "OK", "detail": "FastAPI HTTP Ingest listening on :8000" },
    "syslog_udp": { "status": "OK", "detail": "UDP listener active on 0.0.0.0:5140" },
    "syslog_tcp": { "status": "OK", "detail": "TCP listener active on 0.0.0.0:5141" },
    "sqlite_storage": { "status": "OK", "detail": "Events database connected (storage/ulpf_events.db)" },
    "raw_evidence_store": { "status": "OK", "detail": "Immutable raw store verified (storage/raw/)" },
    "ai_engine": { "status": "OK", "detail": "Local AI model engine ready (offline fallback active)" },
    "file_watcher": { "status": "OK", "detail": "Watchdog active on storage/logs/" }
  }
}
```

#### `GET /api/v1/test/ports`
Probes all network socket ingress ports on the host and returns individual status, protocol, and round-trip latency.

**Query Parameters**:
* `host` (optional, default: `127.0.0.1`): Host to probe.

**Response `200 OK`**:
```json
{
  "host": "127.0.0.1",
  "probes": [
    { "id": "http", "name": "HTTP REST API", "port": 8000, "protocol": "HTTP", "status": "online", "latency_ms": 1.2, "detail": "HTTP 200 OK" },
    { "id": "udp", "name": "Syslog UDP", "port": 5140, "protocol": "UDP", "status": "ready", "latency_ms": 0.4, "detail": "UDP socket ready" },
    { "id": "tcp", "name": "Syslog TCP", "port": 5141, "protocol": "TCP", "status": "online", "latency_ms": 1.1, "detail": "TCP socket connected" }
  ]
}
```

---

### 2. Core Log Ingestion & Batch File Processing

#### `POST /api/v1/ingest`
Primary high-speed single-log ingestion endpoint. Performs SHA-256 evidence hashing, format classification, semantic normalization into ULPF-IR, SQLite persistence, and OpenSearch indexing.

**Request**:
```json
{
  "raw_log": "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|vulnerability|9|src=192.168.1.50 dst=10.0.0.1 spt=49152 dpt=80 proto=tcp act=block",
  "source_id": "Edge-FW-01"
}
```

**Response `200 OK`**:
```json
{
  "status": "success",
  "event_id": "ULPF-2026-1044",
  "format": "cef",
  "confidence": 0.99,
  "raw_sha256": "8f481f185c7c975a8940b5d5d8523c14828b030b42f6381084221a719d3f1107",
  "normalized_event": {
    "event": {
      "id": "ULPF-2026-1044",
      "timestamp": "2026-09-09T01:30:15.000Z",
      "category": "network",
      "action": "block"
    },
    "source": { "ip": "192.168.1.50", "port": 49152 },
    "destination": { "ip": "10.0.0.1", "port": 80 },
    "network": { "transport": "tcp" },
    "device": { "vendor": "PaloAlto", "product": "PAN-OS" }
  }
}
```

#### `POST /api/v1/upload`
High-capacity multipart log file upload endpoint. Ingests full log files (`.log`, `.txt`, `.raw`, `.json`, `.csv`, `.cef`, `.syslog`), processing each line with format recognition, semantic normalization, and database storage.

**Request**: Multipart form-data with `file`: `UploadFile`.

**Response `200 OK`**:
```json
{
  "status": "success",
  "filename": "perimeter_firewall_burst.log",
  "bytes_received": 145020,
  "lines_processed": 500,
  "success_count": 498,
  "unparsed_count": 2,
  "processing_time_ms": 84.5,
  "sample_events": [
    {
      "event_id": "ULPF-2026-1001",
      "format": "cef",
      "raw_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      "status": "success"
    }
  ]
}
```

---

### 3. Events Ledger & Forensics Tamper-Evident Verification

#### `GET /api/v1/events`
Query normalized events ledger stored in SQLite (`storage/ulpf_events.db`).

**Query Parameters**:
* `limit` (default: 50, max: 1000): Number of events to return.
* `vendor` (optional): Filter by vendor (`PaloAlto`, `Cisco`, `Fortinet`, etc.).
* `severity` (optional): Filter by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* `category` (optional): Filter by event category (`network`, `authentication`, `system`, `ids`).

#### `GET /api/v1/events/{id}/verify`
Cryptographic tamper-evidence audit. Recalculates the SHA-256 digest of the stored raw log byte-for-byte and compares it against the stored signature.

**Response `200 OK`**:
```json
{
  "event_id": "ULPF-2026-1044",
  "is_valid": true,
  "status": "VERIFIED_TAMPER_EVIDENT",
  "stored_sha256": "8f481f185c7c975a8940b5d5d8523c14828b030b42f6381084221a719d3f1107",
  "computed_sha256": "8f481f185c7c975a8940b5d5d8523c14828b030b42f6381084221a719d3f1107",
  "bytes_verified": 142,
  "details": "Cryptographic signature matches raw payload byte-for-byte. Stored evidence is mathematically immutable."
}
```

---

### 4. Unknown Logs Quarantine & AI Onboarding

#### `GET /api/v1/unknown/queue`
Retrieves logs that failed static signature detection (confidence < 0.70) queued for AI onboarding.

#### `POST /api/v1/ai/synthesize-parser`
Dispatches an unknown log format to the local AI engine (Ollama / offline SLM) to automatically infer field delimiters, regex extractors, and field mapping schemas.

**Request**:
```json
{
  "raw_samples": [
    "[SCADA-MODBUS-HEX] ADDR:0x04 FUNC:0x03 REG:0x1000 LEN:0x0004 DATA:0x00A1 SENSOR:TURBINE_PRESSURE STATUS:WARNING"
  ]
}
```

**Response `200 OK`**:
```json
{
  "format_name": "scada_modbus_hex",
  "confidence": 0.94,
  "regex_pattern": "\\[(?P<header>[^\\]]+)\\] ADDR:(?P<addr>0x[0-9A-Fa-f]+) FUNC:(?P<func>0x[0-9A-Fa-f]+) REG:(?P<reg>0x[0-9A-Fa-f]+) LEN:(?P<len>0x[0-9A-Fa-f]+) DATA:(?P<data>0x[0-9A-Fa-f]+) SENSOR:(?P<sensor>\\w+) STATUS:(?P<status>\\w+)",
  "field_mappings": {
    "addr": "device.address",
    "sensor": "device.sensor_name",
    "status": "event.action"
  }
}
```

#### `POST /api/v1/ai/reason-threat`
Maps security logs to MITRE ATT&CK techniques with incident reasoning.

#### `POST /api/v1/ai/nl-query`
Translates natural language security analyst queries (e.g., "show failed logins from yesterday") into OpenSearch DSL query syntax.

#### `POST /api/v1/ai/generate-sigma`
Synthesizes standard YAML Sigma detection rules from observed exploit traffic.

---

## Part 2: Testing Simulator Hub API (`:8050`)

The Testing Hub provides specialized endpoints for synthetic telemetry dispatch, cyber attack simulation, stress testing, and remote server targeting:

### 1. Remote Server Connectivity & Health Radar

#### `GET /api/test/target-status`
Executes concurrent Python socket handshakes and probes directly from the testing backend to the target machine host across HTTP/HTTPS, Syslog UDP, Syslog TCP, SSE broadcast, and Local AI ports. **Bypasses browser CORS restrictions, respects split-horizon internal routing, and automatically recovers from cloud hairpin NAT.**

**Query Parameters / JSON Body**:
* `host` (default: `127.0.0.1`): Remote server IP or hostname.
* `api_port` (default: `8000`): Remote HTTP REST API port.
* `udp_port` (default: `5140`): Remote Syslog UDP port.
* `tcp_port` (default: `5141`): Remote Syslog TCP port.
* `ollama_port` (default: `11434`): Local AI inference port.
* `scheme` (default: `http`): Protocol scheme (`http` or `https`).

**Response `200 OK`**:
```json
{
  "host": "192.168.1.50",
  "api_port": 8000,
  "scheme": "http",
  "version": "1.0.0 Enterprise (Phase 8)",
  "platform": "ULPF Dual-Core Sovereign Telemetry Architecture",
  "ports": {
    "http_api": { "port": 8000, "protocol": "HTTP", "status": "healthy", "latency_ms": 2.4, "detail": "HTTP Ingestion API on 192.168.1.50:8000" },
    "syslog_udp": { "port": 5140, "protocol": "UDP", "status": "ready", "latency_ms": 0.8, "detail": "UDP socket opened to 192.168.1.50:5140" },
    "syslog_tcp": { "port": 5141, "protocol": "TCP", "status": "online", "latency_ms": 2.1, "detail": "TCP Syslog Collector on 192.168.1.50:5141" },
    "sse_stream": { "port": 8000, "protocol": "SSE / HTTP", "status": "online", "latency_ms": 1.2, "detail": "Real-Time Event Stream Broadcast active" },
    "ai_engine": { "port": 11434, "protocol": "OLLAMA (qwen2.5:7b)", "status": "online", "latency_ms": 1.8, "detail": "Local Sovereign AI Model Engine (Qwen 7B) active" },
    "merkle_vault": { "port": 8000, "protocol": "MERKLE / S3", "status": "online", "latency_ms": 0.4, "detail": "Cryptographic SHA-256 Merkle Ledger & MinIO immutable vault operational" }
  },
  "all_ready": true
}
```

#### `POST /api/test/ping`
Probes a specific target host, port, and protocol (`http`, `https`, `udp`, `tcp`).

---

### 2. Synthetic Telemetry Dispatch

#### `POST /api/test/send-log`
Transmits a single synthetic log payload to the designated target server across UDP, TCP, or HTTP.

**Request**:
```json
{
  "protocol": "UDP",
  "host": "127.0.0.1",
  "port": 5140,
  "message": "<134>1 2026-09-09T01:30:00Z fw.corp app - - - traffic allow src=10.0.1.15 dst=1.1.1.1",
  "source": "Virtual-PaloAlto-01",
  "vendor": "PaloAlto",
  "scheme": "http"
}
```

#### `POST /api/test/stream-scenario`
Executes one of the 6 cyber attack scenarios against the target server:
* `brute_force`: Rapid SSH credential brute force on TCP `:5141`.
* `sqli`: SQL injection WAF exploit payload.
* `port_scan`: 12-port horizontal reconnaissance sweep.
* `blacklisted_ip`: Ingress attempt from known botnet controller.
* `tamper`: Cryptographic SHA-256 evidence bit-flip integrity test.
* `unknown_scada`: Proprietary SCADA MODBUS-HEX frame.

#### `POST /api/test/burst`
High-throughput stress generator. Emits rapid packet storms with live performance calculation.

**Request**:
```json
{
  "host": "127.0.0.1",
  "port": 5140,
  "protocol": "UDP",
  "count": 100,
  "pacing_delay_ms": 0,
  "scheme": "http"
}
```

#### `POST /api/test/upload-file`
Proxies or dispatches an uploaded log file to the target server across 4 transport modes:
* `http_upload`: Multipart POST to `${scheme}://${host}:${port}/api/v1/upload`.
* `udp_stream`: Line-by-line datagram replay across UDP (port 5140).
* `tcp_stream`: Line-by-line persistent stream replay across TCP (port 5141).
* `file_drop`: Writes file to server watched directory (`storage/logs/`).

---

### 3. Automated Test Pipeline Runner

#### `POST /api/test/pipeline/run`
Triggers non-blocking execution of the automated regression pipeline (`test_pipeline.bat`).

**Request**:
```json
{
  "stage": "all",
  "bench_events": 1000
}
```
Supported `stage` filters: `all`, `fast`, `suites`, `smoke`, `security`, `stack`, `bench`.

#### `GET /api/test/pipeline/status`
Polls current execution status, individual stage timers, verdicts, and live terminal output lines.

**Query Parameters**:
* `offset` (default: 0): Log line offset for incremental live streaming.

---

### 4. Transmission History & Sample Files

* `GET /api/test/sample-files`: Returns curated sample files (Palo Alto, Cisco, Suricata, Linux, SCADA) for 1-click loading.
* `GET /api/test/history`: Returns in-memory audit ledger of synthetic transmissions.
* `DELETE /api/test/history`: Clears the session transmission audit ledger.
