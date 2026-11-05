# ULPF Testing Simulator Hub & Workbench Guide

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

---

## 1. Overview & Architecture

The **ULPF Testing Simulator Hub** is an independent, browser-accessible testing laboratory running on **Port `8050`**:
* **URL**: `http://127.0.0.1:8050`
* **Startup Script**: `start_testing.bat` (or `python testing/server/sim_server.py`)
* **Palette Compliance**: Designed strictly with the 4-color palette (`#EDE9E6`, `#C9996B`, `#5C4F4A`, `#5C766D`).
* **Architectural Decoupling**: Completely segregated from the production server (port `8000`), ensuring that synthetic traffic, attack simulations, and stress tests never pollute production pipelines.

---

## 2. Remote Machine & Target Server Controller

At the top of every tab in the Testing Hub is the **Target Machine Controller Bar**:

```
[  TARGET MACHINE: ] [ http:// ▼ ] [ 192.168.1.50 ] : [ 8000 ] [ Preset Machine... ▼ ] [ ● ONLINE (12ms) ] [  Ping API ] [  Ports ]
```

### 2.1 Configuration Controls:
1. **Protocol Scheme Selector**: Toggle between `http://` (standard) and `https://` (TLS/cloud endpoints).
2. **Target Host / IP Input** (`#targetHostInput`):
   - Accepts raw IPv4/IPv6 addresses (`192.168.1.50`).
   - Accepts DNS hostnames (`ulpf.corp.internal`, `ulpf.cloud`).
   - Supports pasted URLs (`http://192.168.1.50:8000/api/v1`) — an integrated smart parser automatically extracts scheme, host, and port without breaking.
3. **API Port Input** (`#targetPortInput`): Configurable HTTP REST port (default: `8000`).
4. **Machine Presets Dropdown**:
   - ` Localhost (127.0.0.1:8000)`
   - ` Docker Host (host.docker.internal:8000)`
   - ` Remote LAN Machine...` (prompts for LAN IP)
   - ` Remote Cloud / VPS...` (prompts for domain / HTTPS URL)
5. **Live Health Status Pill**: Displays green `ONLINE (12ms)` or red `OFFLINE (timeout)` with real-time ping latency.
6. ** Ping API**: Sends an immediate on-demand socket probe.
7. ** Ports Modal Trigger**: Opens granular transport configuration.

### 2.2 Remote Endpoints Configuration Modal (` Ports`)
Allows configuring:
* **Protocol Scheme**: `http` / `https`
* **Target Host / IP**: Remote IP or hostname
* **HTTP API Port**: Default `8000`
* **Syslog UDP Port**: Default `5140`
* **Syslog TCP Port**: Default `5141`
* **Socket Timeout**: Default `3000 ms`
* **Auto-Probe Frequency**: `Paused`, `5 seconds`, or `10 seconds`
* **Buttons**: ` Save & Apply`, ` Test Ping`, ` Reset Defaults`

### 2.3 Browser CORS Bypass, Split-Horizon DNS & Hairpin NAT Tolerance
When the ULPF server is hosted on a remote machine, cloud instance (such as Oracle Cloud Infrastructure / OCI), or local container network, browsers may block direct cross-origin requests or encounter hairpin NAT routing limitations.
* **Backend Socket Proxying**: Health radar checks and synthetic log dispatches are proxied through `/api/test/target-status` and `/api/test/send-log` on the simulator backend (`testing/server/sim_server.py`), executing raw Python socket handshakes directly to the target machine without CORS or mixed-content restrictions.
* **Split-Horizon DNS & Hairpin NAT Fallback**: When testing against a server running on the same host or cloud VM (where the public IP is not routable back to the host via NAT loopback), the simulator detects internal loopback (`127.0.0.1` / `ulpf-api:8000`) vs public interface probes, seamlessly maintaining accurate socket status indicators.
* **Hybrid Fallback Check**: The frontend (`testing/web/simulator.js`) pairs the backend `/api/test/target-status` probe with a fast direct HTTP fetch probe (`/api/v1/health` with `mode: 'cors'`). If either connection path succeeds, the target machine is immediately registered as `ONLINE`.

---

## 3. Seven Interactive Testing Workbenches

### Tab 1: Virtual Devices & Multi-Vendor Telemetry Streamer
* **Virtual Device Roster**: Palo Alto Networks, Fortinet FortiGate, Cisco ASA, Linux Auth Host, Suricata IDS, AWS WAF, Windows Event Log.
* **Connection State Toggles**: Connect / Disconnect individual virtual devices.
* **Interactive Log Crafting**:
  - Direct fields: Source IP, Destination IP, Dest Port, Action (ALLOW, DENY, DROP, BLOCK), Severity (Low, Medium, High, Critical), Application Protocol.
  - **" Randomize Session"**: Instantly generates randomized IP subnets, target ports, and protocols.
  - Live wire byte length badge.
* **Two-Way Server Receipt Card**:
  - Displays round-trip latency (RTT), assigned ULPF event ID, detected format badge, and computed SHA-256 evidence digest.
* **Continuous Streaming Controller**: Stream logs continuously at 10, 5, 2, or 1 event/sec with animated start/stop toggle.
* **Live Monospaced Terminal Feed**: Real-time wire logs with syntax coloring.

---

### Tab 2: Cyber Threat & Attack Arsenal
A 6-scenario cyber threat simulation arsenal with 1-click execution:
1. ** SSH Credential Brute Force**: Fires 10 rapid failed authentication attempts across ephemeral ports from attacker IP `198.51.100.44` on TCP `5141` to test rate-threshold evaluation.
2. ** SQL Injection (SQLi) Web Exploit**: Injects `UNION SELECT` database exfiltration tokens targeting WAF collectors to verify automated exploit classification.
3. ** Horizontal Port Scan Sweep**: Executes a 12-port reconnaissance sweep across common enterprise ports (`21`, `22`, `53`, `80`, `443`, `3389`, `8080`) from `198.51.100.77`.
4. ** Blacklisted IP Violation**: Ingress attempt from known botnet controller `198.51.100.99`, confirming instant packet discard at the socket layer.
5. ** SHA-256 Tamper Corruption**: Transmits raw telemetry and validates cryptographic hash verification on the server to prove evidence immutability.
6. ** Proprietary SCADA Hex Frame**: Injects non-standard MODBUS-HEX frames (`[SCADA-MODBUS-HEX] ADDR:0x04 FUNC:0x03 CRC:ERROR_FAIL`) to test fallback to AI Onboarding and Human Review queues.
* **Live Defense Verification Console**: Real-time logging of both attack packet delivery and server defense responses.

---

### Tab 3: High-Throughput Load Generator
* **Stress Storming**: Fires continuous recursive bursts of 50, 100, 250, or 500 packets across UDP (`:5140`), TCP (`:5141`), or HTTP REST (`:8000`) using a unified Start/Stop toggle switch.
* **Pacing & Rate Limiting**: Maximum velocity (0ms delay) or paced throughput (100, 50, 10 events/sec).
* **Live Telemetry Radar**:
  - Packets Fired / Requested
  - Delivered OK
  - Effective Speed (`EPS` - Events Per Second)
  - Elapsed Time (`s`)
  - Total Bytes Transferred (`KB`)
* **Visual Progress Bar Track**: Dynamic percentage bar filling during stress storms.

---

### Tab 4: Server Health & Port Radar
* **Status Hero Banner**: Real-time connection status (`ONLINE` / `OFFLINE`), target base URL, and round-trip ping.
* **Port Radar Matrix**:
  - FastAPI REST Ingest (`:8000`)
  - Syslog UDP Ingress (`:5140`)
  - Syslog TCP Stream (`:5141`)
  - Redpanda Streaming Message Bus (`:9092`)
  - MinIO Immutable S3 Storage (`:9000`)
  - OpenSearch Normalized Index (`:9200`)
* **Automated Diagnostic Logging**: Auto-probe timer (5s, 10s, or manual) with live socket handshake traces.

---

### Tab 5: Real Device Guides, Settings & Audit Ledger
* **Agentless Real Device Guides**: Copy-paste configurations for physical network infrastructure:
  - Linux `rsyslog`
  - Windows `NXLog`
  - Cisco ASA & Catalyst
  - Fortinet FortiOS CEF
  - Palo Alto PAN-OS
  - HTTP REST API (cURL and Python)
  - **Dynamic Substitution**: Automatically replaces `TARGET_HOST` and ports with your configured remote server machine IP and custom ports.
  - **1-Click Live Test**: Transmit a sample payload for each device type with 1 click.
* **Transmission Audit Ledger**:
  - Monitored table tracking all synthetic logs transmitted during the session.
  - Protocol filter (`ALL`, `UDP`, `TCP`, `HTTP`).
  - ** Export CSV**: Downloads formatted `ulpf_audit_ledger_<timestamp>.csv`.
  - ** Export JSON**: Downloads raw structured `ulpf_audit_ledger_<timestamp>.json`.
  - ** Clear Ledger**: Clears the session table and server history cache.

---

### Tab 6: Automated Test Pipeline Runner (`test_pipeline.bat`)
* **Direct Web Integration of `test_pipeline.bat`**:
  - Operators can trigger full automated regression, unit, and benchmark tests directly from the Testing Studio with 1 click.
  - **Target Stage Selectors**:
    - ` Run Full Pipeline (All 5 Stages)`
    - ` Fast Smoke Check (--fast)`
    - ` Pytest Test Suites (--suites)` (13 test suites, 61 unit tests)
    - ` End-to-End Smoke Test (--smoke)` (10 verification phases)
    - ` Security & Cyber Resilience (--security)` (8 attack tests)
    - ` Stack & Subsystem Verification (--stack)` (10 runtime subsystem checks)
    - ` Throughput Benchmark (--bench)` (1,000 synthetic packet benchmark)
* **Live Stage Grid & Timers**:
  - 5 interactive cards reflecting live execution state: `IDLE`  ` QUEUED`  ` RUNNING`  ` PASS` / ` FAIL`.
  - Real-time duration timer per stage.
* **Overall Verdict & Summary Box**:
  - Tracks total duration, passed/executed count, active filter, and final execution verdict (` ALL PIPELINE STAGES PASSED [OK]`).
* **Live Pipeline Console**:
  - Monospaced terminal streaming standard output lines in real time with syntax highlighting for `[PASS]`, `[FAIL]`, and stage headers.

---

### Tab 7: Multi-Transport Log File Uploader
* **Drag-and-Drop / Browse Dropzone**: Accepts `.log`, `.txt`, `.raw`, `.json`, `.csv`, `.xml`, `.cef`, `.leef`, `.syslog` up to 10 MB.
* **Interactive File Preview & Raw Editor**: Live line counter, byte size badge, and syntax-highlighted editor allowing pre-flight edits.
* **Automatic Format Recognition**: Evaluates CEF, Syslog RFC, JSON, LEEF, and SCADA hex signatures before transmission.
* **1-Click Curated Test Datasets**: Immediate loading of Palo Alto CEF, Cisco ASA Syslog, Suricata EVE-JSON, Linux Auth, and SCADA Modbus Hex samples.
* **4 Ingestion Transport Modes**:
  1. Direct HTTP REST Upload (`POST /api/v1/upload`).
  2. Sequential UDP Syslog Stream (Port `5140`).
  3. Persistent TCP Syslog Stream (Port `5141`).
  4. File Collector Drop (`storage/logs/`).
* **Live Stat Cards**: Lines processed, normalized OK, unparsed / AI queued, and latency.

---

## 4. Command-Line Test Runners

For headless CI/CD, terminals, or automation scripts:

| Script / Command | Description | Expected Output |
| :--- | :--- | :--- |
| `test_pipeline.bat` | Root automated test pipeline running all 5 regression stages. | `ALL PIPELINE CHECKS PASSED [OK]` |
| `python testing/smoke_test.py` | 10-phase end-to-end smoke test suite. | `10/10 PASS` |
| `python scripts/verify_stack.py` | Subsystems verification (Docker, AI, Redpanda, MinIO). | `10/10 PASS` |
| `python testing/security/security_smoke_test.py` | 8 security & resilience verification tests. | `8/8 PASS` |
| `pytest testing/suites/` | 13 test suites covering parsers, normalizer, and collectors. | `61 passed in ~0.35s` |
| `python testing/benchmarks/benchmark.py --events 1000` | Throughput and latency benchmark. | `> 50,000 EPS` |
