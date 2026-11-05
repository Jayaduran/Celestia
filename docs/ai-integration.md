# ULPF AI Model Integration & Unknown Logs Guide

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

---

## 1. Overview & Sovereign AI Philosophy

National security networks and critical infrastructure operating under strict air-gapped constraints cannot rely on cloud-hosted LLMs (OpenAI, Anthropic, Google Cloud) due to data exfiltration risks and strict offline compliance mandates.

**ULPF integrates sovereign, on-device Artificial Intelligence** designed to operate:
* **100% Offline / Air-Gapped**: Zero outbound telemetry, zero cloud dependencies.
* **Low-Resource Footprint**: Quantized Small Language Models (SLMs) running on commodity CPUs or modest edge GPUs.
* **Deterministic Fallback**: In the absence of a running LLM, ULPF utilizes deterministic heuristic pattern synthesis to ensure uninterrupted operation.

---

## 2. Where & How AI Models Are Integrated

The AI subsystem resides in `app/ai/` and interacts directly with the core pipeline and web API:

```
[ Ingestion Pipeline ] ──> (Unrecognized Log / Confidence < 0.70)
                                      │
                                      ▼
                        [ AI Onboarding Engine ]
                        ├── Ollama Local Daemon (http://localhost:11434)
                        ├── Offline Hugging Face Transformers
                        └── Heuristic Pattern Synthesizer (Fallback)
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       ▼                              ▼                              ▼
1. Parser Synthesis           2. Threat Reasoning           3. NL-Query Translation
& Delimiter Inference         & MITRE ATT&CK Mapping        to OpenSearch DSL
       │                              │                              │
       ▼                              ▼                              ▼
Dynamic Parser Registry       Security Alert Triage         SIEM Analyst Dashboard
(runtime hot-reload)          (T1190, T1110, T1046)         (natural language search)
```

### 2.1 Supported Local Model Configurations:
1. **Ollama Local Engine** (Default Recommended):
   - `deepseek-r1:1.5b` (Fast, high reasoning performance for security rules).
   - `llama3.2:1b` / `llama3.2:3b` (Ultra-low latency schema inference).
   - `qwen2.5-coder:1.5b` / `qwen2.5-coder:3b` (Specialized in regular expression generation).
2. **Offline Quantized Models (GGUF / llama.cpp)**:
   - Run directly on CPU with 4-bit quantization (< 2 GB RAM).
3. **Automated Heuristic Synthesizer (Built-in Zero-Dependency Fallback)**:
   - When no external LLM runner is installed or active, ULPF automatically activates its built-in rule synthesis engine (`app/ai/offline_synthesizer.py`), which uses token frequency analysis, entropy calculation, and delimiter mapping to construct regex parsers deterministically.

---

## 3. Four Core AI Capabilities

### 3.1 Unknown Log Parser Synthesis (`POST /api/v1/ai/synthesize-parser`)
* **Problem**: Proprietary firewalls, legacy mainframes, or industrial SCADA protocols (e.g. Modbus-Hex) emit logs that do not match standard CEF, Syslog, or JSON parsers.
* **AI Solution**: The engine examines sample logs, infers field boundaries, generates a Python-compatible regular expression with named capture groups (`(?P<src_ip>...)`), maps fields to ULPF-IR taxonomy, and registers the new parser dynamically into the runtime engine without server restarts.

### 3.2 Incident Threat Reasoning & MITRE ATT&CK Mapping (`POST /api/v1/ai/reason-threat`)
* **Problem**: Security analysts face alert fatigue and need immediate context on whether an anomalous log represents an active cyber attack.
* **AI Solution**: Evaluates raw log indicators and maps them to MITRE ATT&CK tactics and techniques:
  - SQL Injection attempts  **T1190 (Exploit Public-Facing Application)**
  - SSH login failures  **T1110 (Brute Force Authentication)**
  - Rapid multi-port SYN packets  **T1046 (Network Service Discovery)**
  - Generates recommended mitigation playbooks in human-readable markdown.

### 3.3 Natural Language Query Translation (`POST /api/v1/ai/nl-query`)
* **Problem**: Incident responders shouldn't need to write complex OpenSearch / Elasticsearch DSL JSON queries during time-critical investigations.
* **AI Solution**: Translates plain-English requests into optimized OpenSearch queries:
  - *"Show all blocked SSH attempts from external IPs yesterday"*  
     Generates boolean query with `term: { "action": "block" }`, `term: { "network.transport": "tcp" }`, `term: { "destination.port": 22 }`, and date range filters.

### 3.4 Automated Sigma Detection Rule Synthesis (`POST /api/v1/ai/generate-sigma`)
* **Problem**: Once a novel attack vector is observed, defensive rules must be exported to enterprise SIEMs immediately.
* **AI Solution**: Formats the observed exploit indicators into standard YAML Sigma rules, ready for deployment to Splunk, QRadar, Microsoft Sentinel, or Elastic.

---

## 4. How Logs Get Categorized as "Unknown"

When a raw log string is ingested, it is evaluated through a **4-tier deterministic decision cascade**:

```
[ Ingested Raw Log ]
         │
         ▼
[ Tier 1: Magic Header & Signature Check ]
├── ArcSight CEF signature: CEF:\d+\| ──> Match CEF
├── IBM QRadar LEEF signature: LEEF:\d+(\.\d+)?\| ──> Match LEEF
├── BSD / RFC 5424 Syslog PRI: <\d{1,3}> ──> Match Syslog
└── Valid JSON Envelope: ^\s*\{.*\}\s*$ ──> Match JSON
         │ (No static signature match)
         ▼
[ Tier 2: Token Density & Delimiter Analysis ]
├── Scans for key=value pairs (src=... dst=... action=...)
└── Computes token density ratio
         │ (Token density < 0.70 or irregular delimiters)
         ▼
[ Tier 3: Schema Validation & Mandatory Field Audit ]
├── Validates presence of valid timestamp (ISO 8601, BSD, epoch)
├── Validates source/destination network indicators or device attribution
└── If mandatory fields cannot be extracted ──> Validation Fails
         │
         ▼
[ Tier 4: Unknown Quarantine Fallback ]
├── Confidence Score < 0.70
├── Categorized as: "format": "unknown"
├── Preserves original raw byte payload byte-for-byte
├── Computes SHA-256 evidence integrity seal
└── Queues into storage/ulpf_unknown.db for AI Onboarding & Human Review
```

### Review & Promotion Workflow:
1. **Quarantine Ledger**: View queued unparsed logs via `GET /api/v1/unknown/queue` or the Web Dashboard.
2. **1-Click AI Synthesis**: Operator clicks "Generate Parser" in the UI.
3. **Interactive Validation Diff**: UI shows the AI-generated regex and sample extracted fields side-by-side.
4. **Promotion**: Operator approves the parser via `POST /api/v1/unknown/{id}/onboard`, which permanently adds it to the active parser registry.

---

## 5. Security & Isolation Verification

* **Zero Internet Access**: Verified by running ULPF on an isolated loopback interface with default gateway disabled.
* **No Telemetry Pings**: Codebase contains no external telemetry, analytics beacons, or third-party cloud SDKs.
* **Air-Gapped Container**: Built and validated with `docker-compose.yml` where external port bindings are strictly controlled and network egress is blocked.
