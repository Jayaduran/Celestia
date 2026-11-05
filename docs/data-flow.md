# ULPF Data Flow & Processing Lifecycle

**Universal Log Pre-processing Framework (ULPF)**  
*SIH 26156 — National Technical Research Organisation (NTRO)*

---

## 1. End-to-End Data Pipeline Flow

```
[ Raw Perimeter Device ]
         │ (UDP 514 / REST POST / File Upload)
         ▼
[ Ingestion Gateway ] ──► Compute SHA-256 Hash ──► [ Raw Immutable Store ]
         │
         ▼
[ Format Detector ] (Regex Structural Matching)
         ├── Confidence ≥ 0.70 ──► [ Deterministic Parser ]
         └── Confidence < 0.70 ──► [ AI Parser Studio Quarantine ]
                                              │ (Human / SLM Approval)
                                              ▼
[ ULPF-IR Normalization Engine ] ◄────────────┘
         │
         ├── Apply Security Taxonomy Mapping
         ├── Build Cryptographic Field Provenance Graph
         └── Validate against Pydantic V2 Models
         │
         ▼
[ Canonical Output Dispatcher ]
         ├── OpenSearch / Elasticsearch Index (Real-time Search)
         ├── OCSF (Open Cybersecurity Schema Framework JSON)
         ├── ECS (Elastic Common Schema JSON)
         └── Kafka / Redpanda Streaming Topic
```

---

## 2. Step-by-Step Processing Lifecycle

### Step 1: Ingestion & Cryptographic Hashing
* **Raw Message Ingress**: Received via Syslog UDP listener (`port 514`), REST API endpoint (`POST /process` or `POST /api/v1/events`), or file upload batch.
* **Payload Hashing**: Before any parsing or sanitization, ULPF computes a SHA-256 digest:
  ```python
  raw_hash = hashlib.sha256(raw_bytes).hexdigest()
  ```
* **Immutability Record**: The raw string and hash are stored in the local append-only event store or MinIO S3 bucket under key `raw/{year}/{month}/{day}/{event_id}.log`.

---

### Step 2: Deterministic Format Classification
* The raw payload is passed through the `FormatDetector`:
  1. **JSON Classifier**: Checks for leading/trailing `{...}` or `[...]` and verifies valid JSON structure via fast C-deserializer.
  2. **CEF Classifier**: Inspects for header pattern `^CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|`.
  3. **LEEF Classifier**: Inspects for header pattern `^LEEF:\d+(\.\d+)?\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|`.
  4. **Syslog Classifier**: Checks for RFC 3164 PRI tag `<(\d{1,3})>` or RFC 5424 version tag.
  5. **Key=Value Classifier**: Counts valid `\b([a-zA-Z0-9_\.\-]+)=([^\s"']+|"[^"]*"|'[^']*')` occurrences.
  6. **Unrecognized**: Logs with confidence score < 0.70 are routed to the `Unknown Logs` queue.

---

### Step 3: Parser Execution & Extraction
* **JSON Parser**: Flattens nested JSON hierarchies into dot-notated key-value pairs (e.g. `source.ip: 10.0.0.1`).
* **CEF Parser**: Splits 7 standard prefix fields (`Device Vendor`, `Device Product`, `Device Version`, `Signature ID`, `Name`, `Severity`) and parses the extension string.
* **LEEF Parser**: Splits 5 standard prefix fields and parses tab/custom-delimited key-value attributes.
* **Syslog Parser**: Extracts facility, severity level, timestamp, hostname, application name, process ID, and parses message body.
* **Key=Value Parser**: Tokenizes key-value pairs while respecting double-quoted and single-quoted strings.

---

### Step 4: Canonical Normalization (ULPF-IR v1.0)
The extracted fields are mapped into canonical taxonomy objects:

```json
{
  "event_id": "ULPF-2026-4891",
  "timestamp": "2026-09-06T11:45:00.000Z",
  "vendor": "Palo Alto Networks",
  "product": "PAN-OS Next-Gen Firewall",
  "event_type": "TRAFFIC_DENY",
  "severity": "CRITICAL",
  "action": "DROP",
  "src_ip": "198.51.100.44",
  "src_port": 54120,
  "dst_ip": "10.0.1.15",
  "dst_port": 445,
  "protocol": "TCP",
  "rule_name": "BLOCK_SMB_LATERAL",
  "raw_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### Step 5: Provenance Attribution Graph Generation
Every normalized key retains cryptographic traceability back to the raw payload:

```json
{
  "src_ip": {
    "original_field": "src",
    "original_value": "198.51.100.44",
    "parser": "cef_parser",
    "confidence": 1.0,
    "byte_offset": [68, 82]
  },
  "dst_ip": {
    "original_field": "dst",
    "original_value": "10.0.1.15",
    "parser": "cef_parser",
    "confidence": 1.0,
    "byte_offset": [87, 96]
  }
}
```

---

### Step 6: Downstream Dispatch & Export
1. **OpenSearch / Elasticsearch**: Indexed into `ulpf-events-2026` for sub-millisecond query and SOC analyst visualization.
2. **OCSF Mapping**: Serialized into Open Cybersecurity Schema Framework Class `4001: Network Activity`.
3. **ECS Mapping**: Serialized into Elastic Common Schema format.
4. **Tamper-Evident Verification**: Available via `POST /api/v1/events/{id}/verify-integrity` to recalculate SHA-256 against the stored raw message.
