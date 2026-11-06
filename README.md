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
| **Kosmoporos Landing Page** | [http://localhost:8000/](http://localhost:8000/) | Island Zen Garden enterprise data plane interface & forensic overview |
| **SOC Control Center** | [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) | Live log stream, analytics, and operator inspection console |
| **Operator Auth & Presence** | [http://localhost:8000/login](http://localhost:8000/login) | Operator sign-in modal, session management & telephony presence shield |
| **Testing Web Studio** | [http://localhost:8000/testing/](http://localhost:8000/testing/) | Embedded synthetic traffic generator & 7-phase cyber attack simulator |
| **Dedicated Testbed Server** | [http://localhost:8050/](http://localhost:8050/) | Standalone protocol testing hub container (`ulpf-testing`) |
| **OpenAPI Docs (Swagger)** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive API exploration and OpenAPI schemas |

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
* **Autonomous Telephony Dispatch**: Places automated voice phone alerts via Twilio carrier dispatch whenever verified `CRITICAL` cyber threats (Log4Shell, SQLi DROP TABLE, RCE, SSRF) are detected while no analyst is actively monitoring the console.
* **Telephony Presence Shield**: Periodic browser heartbeats (both logged-in operators and active web visitors) automatically suppress phone calls while the console is open, preventing notification storms.
* **Strict Cooldown Guard**: Enforces an automated 60-second cooldown between repeated telephone calls.
* **Island Zen Garden Landing Page**: High-impact enterprise interface at `/` featuring organic sand ripples, live terminal emulator, real-time Merkle root display, and seamless SOC console entry.
* **Modern Glassmorphic SOC Console**: Real-time investigation center at `/dashboard/` featuring 3 switchable themes (**Dark Obsidian**, **Light Crystal**, and **Luxury Champagne Gold**), IP connection controls, and instant operator status.
* **Dedicated Testing Simulator Hub**: Standalone container service (`ulpf-testing` on port 8050 and reverse-proxied at `/testing/`) offering 7 simulation phases including virtual fleets, threat arsenals, and load cannons.

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
| **Kosmoporos Landing Page & Gateway** | `8000/` (HTTP) | Island Zen Garden landing page, API root, and asset routing |
| **SOC Control Center Dashboard** | `8000/dashboard/` (HTTP) | Live log inspection console, operator presence & theme controls |
| **Embedded Testing Studio** | `8000/testing/` (HTTP) | Reverse-proxied simulator hub inside main gateway |
| **Syslog UDP Collector** | `5140` (UDP) | RFC 3164/5424 UDP log ingestion listener |
| **Syslog TCP Collector** | `5141` (TCP) | RFC 3164/5424 TCP streaming listener |
| **Dedicated Testing Simulator Container** | `8050` (HTTP) | Standalone testing hub container (`ulpf-testing`) |
| **Redpanda Kafka Streaming** | `9092` (Kafka) | Distributed log streaming broker |
| **Redpanda Web Console** | `8085` (HTTP) | Real-time topic and partition inspection |
| **MinIO Immutable S3 Vault** | `9000` / `9001` (HTTP) | Raw byte object store & web management console |
| **OpenSearch Canonical Analytics** | `9200` (HTTP) | Fast distributed JSON search and taxonomy indexing |

---

## 🧪 Testing the Prototype

### Run with Docker Compose
```bash
# Build and launch complete containerized stack (including testing site):
docker compose up -d --build
```

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
Execute the Pytest test suite (including auth and twilio voice suites):
```bash
pytest testing/suites/ -v
```

---

## 📁 Project Structure

```text
Celestia/
├── app/                        # Application orchestration & API layer
│   ├── api/                    # REST routes, schemas, and generators
│   ├── auth/                   # Operator auth sessions & presence shield (manager.py)
│   ├── collectors/             # Network listeners (Syslog UDP/TCP, file tail, redpanda)
│   ├── config/                 # Pydantic environment configuration (settings.py)
│   ├── detector/               # Magic-byte log format detector
│   ├── normalization/          # ULPF-IR canonical normalizer & taxonomy
│   ├── notifications/          # Twilio voice telephony dispatcher & cooldown guard
│   ├── parsers/                # Parsers for CEF, Syslog, JSON, KV, CSV, Cisco, Fortinet
│   ├── storage/                # SQLite metadata and raw log persistence
│   └── main.py                 # FastAPI application definition and mounts
├── dashboard/                  # SOC Control Center Single Page App (HTML, CSS, JS)
│   ├── index.html              # Modern glassmorphic SOC console
│   ├── app.js                  # Frontend controllers, presence heartbeat & live charts
│   └── style.css               # Multi-theme design system (Dark, Light, Luxury)
├── landing/                    # Island Zen Garden Cybersecurity Landing Page
│   ├── index.html              # Warm Zen sand landing page with Merkle DAG display
│   ├── app.js                  # Terminal simulator, presence beacon & auth modal
│   └── style.css               # Organic sand ripple design system & responsive layout
├── docs/                       # Architecture, API, and technical documentation
├── kosmoporos/                 # Core engine, Merkle ledger, and parsing logic
├── scripts/                    # Helper scripts (benchmarks, syslog senders, stack verification)
├── storage/                    # Local SQLite database (`ulpf_metadata.db`) and raw log vault
├── testing/                    # Test suites, benchmarks, and Web Simulator hub
│   ├── Dockerfile              # Dedicated container definition for testing site
│   ├── run_testing.py          # Standalone testing hub runner (port 8050)
│   ├── server/                 # Simulator proxy & protocol transmission backend
│   ├── suites/                 # Pytest unit & integration test suites
│   └── web/                    # 7-phase cyber attack & protocol simulator frontend
├── docker-compose.yml          # Production multi-container orchestration stack
├── .env                        # Local configuration & Twilio credentials
├── .env.example                # Template environment settings
├── requirements.txt            # Python dependencies
└── run_main.py                 # Prototype runner
```

---

## 📜 License
Internal prototype implementation for evaluation and testing.
