# NetSentry AI

### AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

> **SIH 2026 | Problem Statement SIH26160 | Team CodeCraft**

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688)
![React](https://img.shields.io/badge/React-18-61DAFB)
![Tests](https://img.shields.io/badge/tests-57%20passing-brightgreen)

NetSentry AI is an evidence-driven security analysis platform for automatically analyzing IPsec VPN traffic and configurations from captured network traffic.

It combines **protocol-aware parsing, stateful IKE analysis, deterministic security rules, encrypted-flow behaviour analysis, explainable findings, risk assessment, and automated remediation guidance** into a single platform.

Instead of requiring analysts to manually inspect thousands of packets, NetSentry AI converts VPN traffic into structured security evidence and actionable findings.

---

## 🎯 Problem

A VPN being successfully established does not necessarily mean that the deployment is secure.

Traditional VPN investigation often requires analysts to manually inspect:

- IKE negotiations
- Security Association parameters
- Encryption and authentication algorithms
- Diffie-Hellman groups
- PFS configuration
- ESP traffic
- Packet sequences and retransmissions
- Traffic-flow behaviour
- Configuration weaknesses

This process becomes difficult when dealing with large PCAP files and multiple VPN sessions.

NetSentry AI addresses this by providing an automated analysis pipeline that transforms raw VPN traffic into an understandable security assessment.

---

# 💡 Solution

NetSentry AI analyzes captured IPsec/IKE traffic through a multi-stage pipeline:

```text
PCAP / VPN Configuration
          │
          ▼
Packet Parsing & Session Correlation
          │
          ▼
IKE / ESP Protocol Identification
          │
          ▼
Stateful IKE Analysis
          │
          ├───────────────┐
          ▼               ▼
Deterministic Rules    Behaviour Analysis
          │               │
          └───────┬───────┘
                  ▼
       Evidence & Findings
                  │
                  ▼
          Risk Assessment
                  │
                  ▼
     Explainable Security Report
                  │
                  ▼
      Remediation Recommendations
```

---

## 📸 Interface Preview

| SOC Assessment Dashboard | Security Findings & Evidence | Remediation Diffs & Checklist |
| :---: | :---: | :---: |
| <img width="100%" alt="Dashboard" src="https://github.com/user-attachments/assets/0eaed9e9-522f-4ff2-94e8-18db0c22b37c" /> | <img width="100%" alt="Findings + Evidence" src="https://github.com/user-attachments/assets/c59cb207-e4c8-4788-93b7-b772ad56973b" /> | <img width="100%" alt="Remediation View" src="https://github.com/user-attachments/assets/cf9015a1-cefe-4faf-8562-8961a54036da" /> |

---

# 🚀 Key Features

## 1. Stateful IKE Analysis

NetSentry AI does not treat packets as isolated events.

It reconstructs the expected IKE negotiation sequence and analyzes the state of the VPN session.

Supported analysis includes:

* IKEv1 (Main Mode, Aggressive Mode)
* IKEv2
* `IKE_SA_INIT`
* `IKE_AUTH`
* `CREATE_CHILD_SA`
* IKE negotiation sequencing
* Incomplete negotiations
* Unexpected state transitions
* Retransmissions and session correlation

---

## 2. IPsec & Cryptographic Assessment

The platform extracts observable cryptographic parameters from VPN negotiations and evaluates them against configurable security rules and standards (RFC 8247, RFC 8221, RFC 7296, NIST SP 800-57).

Analysis includes:

* Encryption algorithms (AES-GCM, AES-CBC, 3DES, DES, Blowfish)
* Authentication / PRF / integrity parameters (HMAC-SHA2, HMAC-SHA1, MD5)
* Diffie-Hellman groups (Groups 1, 2, 5, 14, 19, 20, 21, 31)
* PFS-related parameters where observable
* IKE Security Associations
* ESP Security Associations
* Protocol configuration characteristics
* Deprecated or weak cryptographic configurations

The rule engine provides deterministic findings with supporting evidence.

---

## 3. Hybrid Rule + Behaviour Analysis

NetSentry AI combines two complementary approaches:

### Deterministic Security Rules

Used for protocol and cryptographic checks where explicit evidence is available.

### Behaviour Analysis

Used to identify unusual encrypted-flow characteristics that may not be captured by static configuration rules.

This hybrid architecture reduces dependence on a single detection method.

---

## 4. Encrypted Traffic Intelligence

Even when ESP payloads are encrypted, observable flow characteristics can still provide useful behavioural information.

NetSentry AI extracts 14 mathematically grounded flow-level statistical features:

1. `packet_count` — Total packet count in the session
2. `bytes_sent` — Total uplink payload bytes (initiator $\to$ responder)
3. `bytes_received` — Total downlink payload bytes (responder $\to$ initiator)
4. `mean_packet_size` — Mean outer packet size in bytes
5. `packet_size_variance` — Variance of packet sizes (dispersion metric)
6. `min_packet_size` — Minimum observed packet size (MTU/frame floor)
7. `max_packet_size` — Maximum observed packet size (MTU bound)
8. `packets_per_sec` — Average packet throughput (packets/sec)
9. `bytes_per_sec` — Average byte throughput (bytes/sec)
10. `duration_seconds` — Total session active duration
11. `mean_inter_arrival_time` — Mean time delta between consecutive packets (sec)
12. `var_inter_arrival_time` — Variance of packet inter-arrival times (jitter proxy)
13. `downlink_uplink_ratio` — Ratio of downlink payload bytes to uplink bytes
14. `burst_factor` — Maximum packet size relative to mean packet size

These features are used to classify broad traffic behaviours such as:

* Web
* VoIP
* Video
* Messaging-like
* Email-like
* ICMP
* Bulk / Data
* Unknown

### Important limitation

NetSentry AI does **not** claim to decrypt ESP traffic or identify an exact application from encrypted packets.

Traffic classification is based on observable flow-level characteristics and should be interpreted as behavioural classification.

---

# 🔍 Evidence-Driven Findings

Every security finding is designed to retain its supporting evidence.

A finding can include:

* Finding
* Severity
* Evidence
* Impact
* Detection method
* Confidence
* Reference
* Recommendation

This allows analysts to move from:

```text
Finding
   ↓
Why was it detected?
   ↓
What packet / parameter supports it?
   ↓
What is the security impact?
   ↓
How can it be remediated?
```

---

# 👁️ Observability Model

Encrypted VPN traffic creates an important limitation: not every security parameter can be directly observed from a passive PCAP.

NetSentry AI therefore distinguishes between:

### OBSERVED

Directly available from packet contents or protocol fields (e.g., IKE exchange types, unencrypted SA proposals, ESP SPIs, outer IP addresses).

### INFERRED

Derived from available evidence with a defined level of confidence (e.g., Tunnel Mode vs. Transport Mode derived from IP endpoint topology and MTU framing; traffic profile category).

### NOT OBSERVABLE

Information that cannot be reliably determined from the available traffic alone (e.g., inner IP payload contents, Child SA PFS status when negotiated exclusively within encrypted `IKE_AUTH` or `CREATE_CHILD_SA` payloads without pre-shared keys).

This prevents the system from presenting assumptions as confirmed facts.

---

# 📋 Current Implementation Status

To maintain scientific and forensic integrity for the SIH technical jury, NetSentry AI explicitly maps its capabilities against the Observability Taxonomy:

| Capability / Requirement | Implementation Status | Observability Level | Notes & Constraints |
| :--- | :--- | :--- | :--- |
| **IKEv1 / IKEv2 Dissection** | **Implemented** | `OBSERVED` | Native raw IPv4 (`DLT_IPV4`), Ethernet, and Linux SLL parsing via Scapy / dpkt |
| **DH Group / Cipher Extraction** | **Implemented** | `OBSERVED` | Decoded directly from unencrypted `IKE_SA_INIT` and Main Mode proposals |
| **IKE State Machine Tracking (FSM)** | **Implemented** | `OBSERVED` | Reconstructs exchange sequences, flags retransmissions & abnormal transitions |
| **Deterministic RFC Rule Engine** | **Implemented** | `OBSERVED` | Evaluates parameters against RFC 8247, RFC 8221, and NIST SP 800-57 |
| **ESP Traffic Correlation** | **Implemented** | `OBSERVED` | Merges protocol 50 data flows with IKE sessions by IP endpoint tuple |
| **Replay Protection Detection** | **Implemented** | `OBSERVED` | Verifies monotonically increasing 32-bit sequence numbers in outer ESP headers |
| **14 Encrypted Flow Features** | **Implemented** | `OBSERVED` | Derived mathematically from outer packet sizes, timestamps, and directional bytes |
| **Behavioural Traffic Classifier** | **Implemented** | `INFERRED` | Random Forest classifier categorizes flow patterns (Web, VoIP, Video, Bulk) |
| **Unsupervised Anomaly Detection** | **Implemented** | `INFERRED` | Isolation Forest flags out-of-distribution flow signatures |
| **Explainable ML (Tree SHAP)** | **Implemented** | `INFERRED` | Computes top feature attributions explaining anomaly score contributions |
| **Tunnel vs Transport Mode** | **Implemented** | `INFERRED` | Inferred from gateway IP endpoint topology and MTU framing characteristics |
| **PFS Configuration in Child SA** | **Policy-Dependent** | `NOT OBSERVABLE` | Marked `NOT OBSERVABLE` in passive captures when secondary exchange is encrypted |
| **Inner Application Decryption** | **Excluded** | `NOT OBSERVABLE` | Cryptographic boundary strictly preserved; zero payload decryption claimed |
| **Safe Remediation Diffs** | **Implemented** | N/A | Syntactic diffs (`swanctl.conf` / Cisco IOS-XE), pre-flight checks, rollback steps |
| **Dual PDF Audit Reports** | **Implemented** | N/A | Generates Executive Brief (1-2 pages) & Forensic Audit PDF (with 7-column matrix) |

---

# 🛡️ Security Assessment

NetSentry AI evaluates VPN sessions for security-relevant conditions including:

* Weak or deprecated cryptographic configurations
* Suspicious IKE negotiation behaviour
* Incomplete or abnormal handshakes
* Configuration deviations
* PFS-related policy findings
* Metadata exposure
* Unusual encrypted-flow behaviour

Findings are consolidated into a security assessment with severity and supporting evidence.

---

# 📊 Risk Assessment

NetSentry AI converts identified findings into a consolidated **0–100 security risk score**.

The score is based on the configured finding severity and assessment methodology.

The platform also provides a threat/risk matrix containing:

| Field | Description |
| :--- | :--- |
| **Finding** | Detected security condition |
| **Severity** | Relative security impact (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| **Evidence** | Supporting protocol/traffic evidence |
| **Impact** | Potential consequence |
| **Confidence** | Detection confidence where applicable |
| **Reference** | Relevant security/protocol reference (RFC / NIST) |
| **Recommendation** | Suggested corrective action |

---

# 🕵️ Metadata Exposure Analysis

IPsec encryption protects payload contents, but some traffic metadata remains observable.

NetSentry AI analyzes observable metadata including:

* Network endpoints
* IKE signaling ports
* Security Parameter Indexes (SPIs)
* Packet volume
* Packet-size patterns
* Timing characteristics

This helps analysts understand what information can remain visible even when the payload is encrypted.

---

# 🔧 Automated Remediation Guidance

For identified configuration weaknesses, NetSentry AI can generate remediation guidance and configuration proposals.

Current remediation output includes:

* strongSwan configuration guidance (`swanctl.conf`)
* Cisco IOS-XE configuration templates
* Cryptographic parameter recommendations
* PFS-related configuration guidance
* Syntactic configuration diffs
* Pre-flight interoperability checklist
* Rollback procedure

Remediation output is intended as a proposed configuration change and should be reviewed before deployment. NetSentry AI never pushes unverified changes automatically to live network appliances.

---

# 🧪 VPN Testbed & Reproducible Testing

NetSentry AI includes a controlled testbed approach for generating reproducible VPN traffic.

Test configurations can vary across:

* IKE versions (IKEv1, IKEv2)
* Tunnel / Transport mode
* IPv4 / IPv6
* AES-128
* AES-256
* AES-GCM
* AES-CBC + HMAC
* Different DH groups (Groups 1, 2, 5, 14, 19, 20, 31)
* PFS enabled / disabled

Controlled traffic profiles can include:

* Web
* VoIP
* Video
* Messaging-like traffic
* Email-like traffic
* ICMP
* Bulk data

This provides labelled traffic for development and controlled validation.

---

# 🧩 Architecture

```text
                    ┌─────────────────────┐
                    │   PCAP / Config     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Packet Parser       │
                    │ Scapy / dpkt        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Session Correlation │
                    │ IKE / ESP / SA      │
                    └──────────┬──────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
      ┌─────────────────┐             ┌─────────────────┐
      │ Stateful IKE    │             │ Flow Feature    │
      │ FSM             │             │ Extraction      │
      └────────┬────────┘             └────────┬────────┘
               │                               │
               ▼                               ▼
      ┌─────────────────┐             ┌─────────────────┐
      │ Rule Engine     │             │ ML / Behaviour  │
      └────────┬────────┘             │ Analysis        │
               │                      └────────┬────────┘
               └──────────────┬───────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Evidence & Findings │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Risk & Threat       │
                    │ Assessment          │
                    └──────────┬──────────┘
                               ▼
              ┌────────────────┴────────────────┐
              ▼                                 ▼
     ┌─────────────────┐              ┌─────────────────┐
     │ Dashboard       │              │ Reports &       │
     │                 │              │ Remediation     │
     └─────────────────┘              └─────────────────┘
```

---

# 🛠️ Technology Stack

## Backend

* Python 3.12+
* FastAPI & Uvicorn
* Scapy & dpkt
* SQLAlchemy & aiosqlite / asyncpg
* SQLite / PostgreSQL

## Machine Learning

* Scikit-learn
* XGBoost
* SHAP (Tree SHAP)
* NumPy & Pandas

## Frontend

* React 18
* Vite
* Tailwind CSS
* Lucide React Icons
* Axios

## Security & Processing

* IKE / IPsec protocol analysis
* Stateful finite-state-machine analysis
* Deterministic security rules (RFC 8247, RFC 8221, NIST SP 800-57)
* 14-dimensional flow-level feature extraction
* Explainable ML feature attribution

## Reporting

* ReportLab
* Executive security brief PDF (1-2 pages)
* Comprehensive technical forensic audit PDF
* Syntactic configuration diffs (`swanctl.conf` / Cisco IOS-XE)

---

# 📁 Project Structure

```text
NetSentry-AI/
│
├── backend/
│   ├── app/
│   │   ├── engines/           # Rule engine, FSM, Threat Matrix, Remediation
│   │   ├── ml/                # XGBoost, Isolation Forest, Flow Features, Classifier
│   │   ├── parsers/           # IKE/ESP parser (Scapy/dpkt), Live capture
│   │   ├── reports/           # PDF Report generator (Executive & Technical)
│   │   ├── routers/           # FastAPI endpoints (Ingest, Assessment, ML, Testbed)
│   │   ├── testbed/           # VPN config generator & traffic synthesizer
│   │   ├── config.py
│   │   ├── models.py
│   │   └── schemas.py
│   ├── tests/                 # Automated pytest test suite (57 tests)
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/        # React UI components (ThreatMatrix, Remediation, etc.)
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
│
├── testbed/
│   └── captures/              # Controlled test captures (Web, VoIP, Video)
│
├── README.md
└── LICENSE
```

---

# ⚙️ Installation

## Prerequisites

* Python 3.12+
* Node.js 18+
* npm 9+
* Git

## Clone the repository

```bash
git clone https://github.com/your-username/netsentry-ai.git
cd netsentry-ai
```

## Backend Setup

```bash
cd backend
python -m venv venv
```

### Windows

```powershell
.\venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Frontend Setup

```bash
cd ../frontend
npm install
```

---

# ▶️ Running the Application

### 1. Start the Backend API

```powershell
cd backend
.\venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

* **Interactive OpenAPI/Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 2. Start the Frontend Dashboard

```bash
cd frontend
npm run dev
```

* **Web Application**: [http://localhost:3000](http://localhost:3000)
* **Default Analyst Credentials**:
  * **Username**: `analyst`
  * **Password**: `Password123!`

---

# 🧪 Example Analysis Workflow

```text
1. Upload a PCAP
        ↓
2. NetSentry parses IKE / ESP traffic (supports Ethernet & DLT_IPV4 raw frames)
        ↓
3. Sessions and Security Associations are correlated
        ↓
4. Stateful IKE analysis reconstructs negotiation behaviour
        ↓
5. Cryptographic rules evaluate observable parameters
        ↓
6. Flow features are extracted from encrypted traffic
        ↓
7. Behaviour analysis evaluates traffic patterns
        ↓
8. Findings are generated with evidence
        ↓
9. Risk assessment is calculated
        ↓
10. Dashboard and technical report are generated
        ↓
11. Remediation guidance is provided
```

---

# 📈 Validation

Validation is performed using controlled VPN testbed traffic and reproducible PCAP captures.

The validation process checks:

* Correct IPsec detection
* IKE version identification
* IKE exchange identification
* ESP detection
* Security Association parameter extraction
* Stateful negotiation analysis
* Rule-engine findings
* Flow feature extraction
* Traffic classification
* Evidence generation
* Report generation

### Automated Test Suite

Run the full automated pytest suite:

```bash
cd backend
pytest -v
```

```text
======================= 57 passed in 8.75s =======================
```

### Validation Principle

Performance claims are reported only for the datasets and controlled test conditions used during validation.

Synthetic or controlled traffic results should not be interpreted as proof of equivalent performance on all real-world VPN deployments.

---

# 🔐 Security & Privacy

PCAP files can contain sensitive network information.

NetSentry AI is designed with the following principles:

* Analyse only authorized captures
* Avoid unnecessary payload exposure
* Treat uploaded PCAPs as sensitive data (encrypted at rest using Fernet AES-256)
* Restrict access to stored analysis results via Role-Based Access Control (RBAC)
* Support controlled retention and deletion policies
* Do not claim to decrypt protected ESP payloads

---

# 🎯 Why NetSentry AI?

NetSentry AI brings multiple stages of VPN security analysis into one workflow:

```text
Protocol Analysis
       +
Stateful IKE Analysis
       +
Cryptographic Assessment
       +
Behaviour Analysis
       +
Evidence & Explainability
       +
Risk Assessment
       +
Remediation
```

The objective is not simply to detect that a VPN exists.

The objective is to help an analyst answer:

> **What is happening?  
> Is the VPN configured securely?  
> What evidence supports the finding?  
> What behaviour is visible from encrypted traffic?  
> What should be fixed?**

---

# 🏆 SIH 2026

**Problem Statement:** SIH26160  
**Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Team:** CodeCraft  
**Project:** NetSentry AI

### Core Deliverables

* Working VPN protocol analysis platform
* IPsec/IKE analysis engine
* Stateful IKE analysis
* Security rule engine
* Encrypted-flow behaviour analysis
* Explainable security findings
* Risk/threat assessment
* Interactive dashboard
* Automated security reporting
* Remediation guidance
* Controlled VPN testbed and validation dataset

---

# 📚 References

* **NIST SP 800-77 Rev. 1** — Guide to IPsec VPNs
* **RFC 7296** — Internet Key Exchange Protocol Version 2 (IKEv2)
* **RFC 8247** — Internet Key Exchange Version 2: Cryptographic Algorithms
* **RFC 8221** — Cryptographic Algorithm Implementation Requirements for ESP and AH
* **RFC 4301** — Security Architecture for the Internet Protocol
* **RFC 4303** — IP Encapsulating Security Payload (ESP)
* **Liu, Ting & Zhou** — Isolation Forest, IEEE ICDM 2008
* Research literature on machine-learning-based encrypted traffic analysis

---

# 👥 Team CodeCraft

Built for **Smart India Hackathon 2026**.

**NetSentry AI**  
*Analyse → Assess → Explain → Secure*
