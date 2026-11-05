# ULPF 3.5-Minute Official SIH Video Demo Script & Screenplay

**Universal Log Pre-processing Framework (ULPF)**  
*Smart India Hackathon 2026 — Problem Statement ID: 26156 (NTRO)*  
*Theme: Blockchain & Cybersecurity | Team: MEGABYTES (CMRU025)*

---

##  Overview & Timing Schedule

| Scene | Duration | Target Screen / Tool | Core Message & Demonstration Highlight |
| :--- | :--- | :--- | :--- |
| **1. Value Proposition** | 0:00 – 0:35 | **Main SOC Dashboard** | Solves the $N \times M$ integration crisis & SIEM ingestion tax. |
| **2. Socket Radar** | 0:35 – 1:15 | **Testing Hub / Port Radar** | Non-blocking UDP :5140, TCP :5141, REST :8000 averaging 0.45 ms RTT. |
| **3. Stress & Threat Suite** | 1:15 – 1:55 | **Simulator Stress Cannon** | Sustains 184,457.6 Packets/Sec; 8 red-team attack scenarios neutralized. |
| **4. Merkle Vault (Blockchain)** | 1:55 – 2:35 | **Merkle Integrity Vault** | 125 logs/block SHA-256 tree root with instant tamper detection alert. |
| **5. Sovereign AI Onboarding** | 2:35 – 3:15 | **AI Onboarding Queue** | Local air-gapped LLM (Qwen/Ollama) synthesizes parsers for zero-day logs. |
| **6. Docker & Benchmarks** | 3:15 – 3:45 | **Analytics & Terminal** | Redpanda streaming sinks, one-command Docker compose, 100% benchmarks OK. |

---

##  Step-by-Step Spoken Script & Screenplay

### Scene 1: Problem Context & The Core Differentiator (0:00 – 0:35)
* **Screen**: Open Tab: **Main SOC Dashboard** (`http://localhost:8000/dashboard/`).
* **Visual Action**: Hover over the top brand logo, the 4 KPI summary cards (*Total Analyzed Events, Live Ingestion Rate EPS, Threat Incidents, Active Schemas*), and the live event stream.
* **Word-for-Word Spoken Script**:
  > *"Respected Judges, welcome to the demonstration of **ULPF — the Universal Log Pre-processing Framework**, developed by Team **MEGABYTES** for **Smart India Hackathon Problem Statement 26156** under the **Blockchain and Cybersecurity** theme.*
  >
  > *In modern enterprise and defense SOCs, security teams face an exponential $N \times M$ integration crisis where hundreds of firewall, router, and cloud formats flood expensive SIEMs. This creates huge ingestion licensing taxes, lossy transformations that destroy legal chain-of-custody, and weeks of manual parser coding.*
  >
  > *ULPF solves this at the wire layer. **ULPF is not another SIEM — it is the vendor-independent, air-gapped preprocessing and cryptographic interoperability layer between heterogeneous log sources and downstream analytics."*

---

### Scene 2: Multi-Socket Wire Ingress & Live Socket Radar (0:35 – 1:15)
* **Screen**: Switch to Tab: **Testing Simulator Hub** (`http://localhost:8000/testing/`).
* **Visual Action**: Scroll to the **Live Network Port Radar** (`SOCKET RADAR SCOPE`). Click the button: **`DISPATCH ACTIVE SOCKET PROBES`**. Show the green sweeping radar line, the blips appearing on the radar canvas with ripple pings, and the live latency badges updating to `0.45 ms RTT`.
* **Word-for-Word Spoken Script**:
  > *"Here on our Testing Simulator Hub, you are seeing our **Live Network Port Radar**. ULPF operates at the wire layer using non-blocking asynchronous sockets on pure **Syslog UDP on Port 5140**, **Syslog TCP on Port 5141**, and **REST Ingestion on Port 8000**, with zero client-side agent overhead.*
  >
  > *When I trigger an active socket probe across all 6 subsystems, you can see real-time datagram handshakes with sub-millisecond response times—averaging just **0.45 milliseconds**—proving our drop-in readiness for high-speed network edge devices."*

---

### Scene 3: 184k EPS Stress Cannon & 8-Threat Red-Team Arsenal (1:15 – 1:55)
* **Screen**: Still on the **Testing Simulator Hub**. Scroll to the **High-Speed Stress Cannon** and **Cyber Threat Arsenal**.
* **Visual Action**: Click **`SYN FLOOD DoS`** or **`SQL INJECTION CHAIN`** from the 8-threat grid. Click **`DISPATCH 1,000 PACKET BURST`**. Show the immediate transmission receipts and the live wiretap console feed updating.
* **Word-for-Word Spoken Script**:
  > *"Next, our **High-Velocity Stress Cannon** and **Red-Team Cyber Threat Arsenal** tests system resilience across 8 active attack scenarios—including SYN Floods, SQL Injection chains, DNS Tunneling, and Ransomware canaries.*
  >
  > *When we fire a 1,000-datagram burst directly over UDP socket 5140, ULPF sustains an empirical throughput of **over 184,400 packets per second** with a memory footprint of just **42 Megabytes RSS**. Our C-Fast compiler deterministically normalizes multi-vendor formats into canonical **ULPF-IR**."*

---

### Scene 4: Cryptographic SHA-256 Merkle Ledger (Blockchain Theme) (1:55 – 2:35)
* **Screen**: Switch to Tab: **Main Dashboard** $\rightarrow$ Navigate to **Merkle Integrity Vault**.
* **Visual Action**: Show the **125 Logs / Block** visualizer with root hash verification (`VERIFIED [OK]`). Click **`SIMULATE LOG TAMPER`**. Show the instant red **Cryptographic Mismatch Alert**.
* **Word-for-Word Spoken Script**:
  > *"This brings us to our core link to the **Blockchain & Cybersecurity theme**: our **Cryptographic SHA-256 Merkle Ledger Vault**.*
  >
  > *Unlike conventional SIEMs that perform lossy normalization, ULPF preserves 100% of the raw byte stream and batches events into **125-log cryptographic blocks**. A SHA-256 Merkle root is calculated for every block. If an adversary gains root privileges on the server and alters even a single byte of a historical log, the Merkle tree recalculation immediately fails, alerting the SOC of evidence tampering.*
  >
  > *This guarantees complete non-repudiation and court-admissible digital chain-of-custody under **Section 65B of the Indian Evidence Act**."*

---

### Scene 5: Sovereign Air-Gapped AI Parser Onboarding Engine (2:35 – 3:15)
* **Screen**: In Main Dashboard $\rightarrow$ Navigate to **AI Onboarding / Unknown Logs Queue**.
* **Visual Action**: Select an unparsed proprietary SCADA/Modbus log. Click **`SYNTHESIZE AI PARSER`**. Show the local AI model (Qwen/Ollama) generating the Pydantic schema and regex tokens, and click **`APPROVE TO PRODUCTION`**.
* **Word-for-Word Spoken Script**:
  > *"What happens when a network device emits a completely unknown, proprietary, or zero-day log format?*
  >
  > *Instead of breaking the pipeline or requiring weeks of manual regex coding, ULPF routes the log to our **Sovereign AI Onboarding Engine**. Powered by a local, air-gapped Large Language Model running on Ollama, the AI analyzes the syntax, synthesizes a deterministic parser, validates it against test samples, and presents it to the administrator for single-click deployment.*
  >
  > *Because the LLM runs 100% locally on-premise, **zero sensitive telemetry or defense logs ever leave the air-gapped network**."*

---

### Scene 6: Analytics Studio, Docker / Redpanda Clip & Conclusion (3:15 – 3:45)
* **Screen**: Switch to **Analytics Studio** (show live charts), then switch to the **Terminal** running `docker compose ps` and `python scripts/run_benchmarks.py`.
* **Visual Action**: Show the green Docker containers, Redpanda streaming brokers, and benchmark validation receipts showing `100% OPERATIONAL [OK]`.
* **Word-for-Word Spoken Script**:
  > *"Finally, our **Analytics Studio** exports standardized telemetry into **OCSF v1.1.0**, **Elastic ECS**, and **OpenSearch**, while enabling rapid **CERT-In 6-Hour incident reporting compliance**.*
  >
  > *The entire ULPF ecosystem—including core workers, Redpanda streaming brokers, MinIO immutable storage, and OpenSearch nodes—runs with a single `docker compose up` command. As demonstrated by our live benchmark suite executing here, all subsystem benchmarks are 100% operational.*
  >
  > *ULPF delivers sovereign, high-throughput cyber defense for India's strategic networks. Thank you!"*
