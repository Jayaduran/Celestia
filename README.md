<div align="center">
  <img src="dashboard/logo.png" alt="Kosmoporos Logo" width="160" style="border-radius: 12px; margin-bottom: 12px;">
  <h1>Kosmoporos (ULPF)</h1>
  <p><strong>Universal Log Pre-processing & Cryptographic Provenance Framework</strong></p>
  <p><em>High-throughput, vendor-neutral log ingestion, canonical normalization, and tamper-evident audit prototype.</em></p>
</div>

---

### 🌐 Quick Access (Local Prototype)

| Interface | Local URL | Description |
| :--- | :--- | :--- |
| **SOC Web Dashboard** | [http://localhost:8000/](http://localhost:8000/) | Live log stream, analytics, and SOC inspection console |
| **Testing Web Studio** | [http://localhost:8000/testing/](http://localhost:8000/testing/) | Synthetic traffic generator and attack vector simulator |
| **OpenAPI Docs (Swagger)**| [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive API exploration and schemas |
| **Dedicated Testbed Server**| [http://localhost:8050/](http://localhost:8050/) | Standalone protocol testing runner |

---

## 📌 Overview

**Kosmoporos** is an air-gapped, high-speed log pre-processing pipeline designed to solve the multi-vendor log ingestion bottleneck. Enterprise and defense Security Operations Centers (SOCs) receive telemetry from heterogeneous appliances (Cisco, Palo Alto, Fortinet, CheckPoint, Windows, Linux) in incompatible formats (Syslog, CEF, LEEF, JSON, Key-Value, CSV).

Kosmoporos intercepts raw logs at the wire layer, normalizes them into a unified canonical schema (**ULPF-IR / OCSF**), and anchors raw data into a **SHA-256 Merkle tree ledger** to ensure court-admissible forensic integrity.

---

## 🚀 Key Features

* **Multi-Protocol Ingestion**: Native Syslog listeners over **UDP (5140)** and **TCP (5141)**, plus high-throughput REST API ingestion.
* **Format Auto-Detection**: Magic-byte pattern matching detects Syslog RFC 3164/5424, CEF, JSON, LEEF, PAN-OS, and Key-Value logs without manual configuration.
* **Fast Deterministic Normalization**: Maps diverse log fields into canonical ULPF-IR and OCSF schemas with byte-level provenance pointers.
* **Cryptographic Tamper-Evidence**: Batches events into 125-log blocks secured by SHA-256 Merkle root hashes for verifiable forensic chain-of-custody.
* **Threat Heuristics**: In-stream detection of common attack patterns including SQLi, XSS, Path Traversal, and brute-force spikes.
* **Modern Glassmorphic Dashboard**: Real-time SOC dashboard featuring 3 switchable themes (**Dark Obsidian**, **Light Crystal**, and **Luxury Champagne Gold**).

---

## ⚡ Quick Start

### 1. Requirements
* **Python 3.10+** (tested on Python 3.13)
* **pip** package manager

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start the Prototype Server
```bash
python run_main.py
```
This boots the FastAPI REST service, Syslog UDP/TCP listeners, SQLite metadata persistence, and the Web Dashboard.

Open [http://localhost:8000/](http://localhost:8000/) in your browser.

---

## 🔌 Local Ports & Services

| Service | Port / Protocol | Details |
| :--- | :--- | :--- |
| **FastAPI REST API & Web Dashboard** | `8000` (HTTP) | Main API server, SSE event stream, and frontend UI |
| **Testing Web Studio** | `8000/testing/` (HTTP) | Embedded simulator inside the main server |
| **Syslog UDP Collector** | `5140` (UDP) | RFC 3164/5424 UDP log ingestion listener |
| **Syslog TCP Collector** | `5141` (TCP) | RFC 3164/5424 TCP streaming listener |
| **Optional Dedicated Simulator** | `8050` (HTTP) | Launched via `python testing/run_testing.py` |

---

## 🧪 Testing the Prototype

### Send Test Syslog Messages
Use the built-in script to dispatch test events to the running server:
```bash
python scripts/send_syslog.py
```

### Run Benchmarks
Measure parser speed and ingestion latency locally:
```bash
python scripts/run_benchmarks.py
```

### Verify System Health
Run the complete stack health check:
```bash
python scripts/verify_stack.py
```

### Run Automated Unit & Integration Tests
Execute the Pytest test suite:
```bash
pytest testing/suites/ -q
```

---

## 📁 Project Structure

```text
Celestia/
├── app/                        # Application orchestration & API layer
│   ├── api/                    # REST routes, schemas, and generators
│   ├── collectors/             # Network listeners (Syslog UDP/TCP, file tail)
│   ├── config/                 # Pydantic environment configuration (settings.py)
│   ├── detector/               # Magic-byte log format detector
│   ├── normalization/          # ULPF-IR canonical normalizer & taxonomy
│   ├── parsers/                # Parsers for CEF, Syslog, JSON, KV, CSV
│   ├── storage/                # SQLite metadata and raw log persistence
│   └── main.py                 # FastAPI application definition and mounts
├── dashboard/                  # Lightweight Web UI (HTML, CSS, JS)
│   ├── index.html              # Single Page Application
│   ├── app.js                  # Frontend controllers and live charts
│   └── style.css               # Multi-theme design system (Dark, Light, Luxury)
├── docs/                       # Architecture, API, and technical documentation
├── kosmoporos/                 # Core engine, Merkle ledger, and parsing logic
├── scripts/                    # Helper scripts (benchmarks, syslog senders, stack verification)
├── storage/                    # Local SQLite database (`ulpf_metadata.db`) and raw log vault
├── testing/                    # Test suites, benchmarks, and Web Simulator hub
├── .env                        # Local configuration
├── .env.example                # Template environment settings
├── requirements.txt            # Python dependencies
└── run_main.py                 # Prototype runner
```

---

## 📜 License
Internal prototype implementation for evaluation and testing.
