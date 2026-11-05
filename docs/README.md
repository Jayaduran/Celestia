# ULPF Technical Documentation Hub

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

Welcome to the official technical documentation repository for the **Universal Log Pre-processing Framework (ULPF)**. This documentation provides comprehensive coverage of system architecture, network log ingestion, REST API specifications, the testing simulator studio, forensic evidence validation, and sovereign on-device AI integration.

---

##  Documentation Index

### 1. System Architecture & Core Concepts
* **[System Architecture](architecture.md)**: High-level architectural overview, decoupled design philosophy, deterministic parsing pipeline, intermediate representation (ULPF-IR), and storage topology.
* **[Two-Page Architecture Summary](architecture_2page.md)**: Concise executive summary of ULPF for presentations and audits.
* **[Data Flow & Event Lifecycle](data-flow.md)**: Detailed trace of a log line from network socket arrival to OpenSearch indexing and tamper-evident archival.
* **[ULPF-IR Canonical Taxonomy](ulpf-ir.md)**: The standard JSON schema definition for normalized logs, compatible with OCSF and Elastic Common Schema (ECS).

### 2. Network Ingestion, Collectors & Storage
* **[Ingestion Architecture & Log Storage](ingestion.md)**: Comprehensive guide to network collectors (Syslog UDP `5140`, Syslog TCP `5141`, REST API `8000`), raw and parsed log storage paths (`storage/raw/`, `storage/ulpf_events.db`, `storage/ulpf_unknown.db`), how logs are categorized as "Unknown", file uploader lab, and connecting remote physical devices.
* **[Forensics & Tamper-Evident Evidence](evidence.md)**: Mathematical and cryptographic proof of SHA-256 evidence integrity, zero-modification raw byte guarantees, and chain of custody compliance.

### 3. API Specifications & Interfaces
* **[REST API & Testing Hub Specification](api.md)**: Complete OpenAPI specification covering both the Main Production Server (`http://127.0.0.1:8000`) and the Testing Simulator Hub (`http://127.0.0.1:8050`).

### 4. Testing & Verification
* **[Testing Simulator Hub & Workbench Guide](testing.md)**: User guide for the port `8050` Testing Studio across all 7 tabs: Virtual Devices, Cyber Attack Arsenal, High-Throughput Load Generator, Server Health Radar, Real Device Guides, Automated Test Pipeline (`test_pipeline.bat`), and Multi-Transport File Uploader. Includes remote server targeting and CORS bypass architecture.
* **[Benchmark & Performance Testing](benchmark.md)**: Ingestion throughput benchmarks (> 50,000 EPS), latency statistics, and stress test methodologies.

### 5. Sovereign Artificial Intelligence
* **[AI Model Integration & Unknown Logs Guide](ai-integration.md)**: Deep dive into offline Small Language Model (SLM) integration, Ollama local engine, 4 core capabilities (Parser Synthesis, Threat Reasoning, NL Query to OpenSearch DSL, Sigma Rule Synthesis), and the 4-phase unknown log quarantine decision cascade.

### 6. Deployment & Operations
* **[Deployment Guide (Comprehensive)](deployment.md)**: Production deployment instructions for Oracle Cloud VM, local bare-metal, and Docker Compose.
* **[Quick-Start Deployment Guide (Root)](../DEPLOYMENT.md)**: Container orchestration inventory, port matrix, and automated deployment scripts (`deploy.sh`, `deploy.ps1`).
* **[System Readiness & Verification Ledger](../working.md)**: Full runtime verification status across all components, ports, and tests.
* **[Air-Gapped & Sovereign Deployment](air-gapped-deployment.md)**: Specific steps for air-gapped national security environments with zero outbound network access.
* **[Known Limitations & Engineering Roadmap](limitations.md)**: Transparent engineering disclosure of current limitations, operational boundaries, and future enhancements.

### 7. Demonstrations & Jury Materials
* **[Live Demo Script](demo-script.md)**: Step-by-step walkthrough for live jury evaluations.
* **[5-Slide Pitch & Defense Presentation](presentation_5slides.md)**: High-impact presentation deck structure for technical defense.
* **[Judge FAQ & Technical Questions](judge-questions.md)**: Comprehensive answers to technical jury and evaluator questions.

---

##  Quick Start: Running the Services

### Option A: One-Command Automated Deployment (Docker)
```bash
# On Linux / Oracle Cloud VM:
chmod +x deploy.sh && ./deploy.sh

# On Windows (PowerShell):
powershell -ExecutionPolicy Bypass -File .\deploy.ps1

# Or standard Docker Compose:
docker compose up -d --build
```

### Option B: Local Windows Batch Launchers
1. **Start the Production Server (Port `8000`)**:
   ```cmd
   start_main.bat
   ```
   * **Dashboard**: `http://localhost:8000/dashboard/index.html`
   * **Swagger API Docs**: `http://localhost:8000/docs`

2. **Start the Testing Simulator Hub (Port `8050`)**:
   ```cmd
   start_testing.bat
   ```
   * **Testing Studio**: `http://localhost:8050`
   * **Testing API Docs**: `http://localhost:8050/docs`

3. **Run Automated Test Pipeline**:
   ```cmd
   test_pipeline.bat
   ```
   Executes all 5 test stages (Pytest suites, Smoke test, Security test, Stack verify, Benchmark).

