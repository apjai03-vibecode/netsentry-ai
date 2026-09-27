# NetSentry AI

### AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

> **SIH 2026 | Problem Statement SIH26160 | Team Code craftss**

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688)
![React](https://img.shields.io/badge/React-18-61DAFB)
![Tests](https://img.shields.io/badge/tests-57%20passing-brightgreen)

NetSentry AI is an evidence-driven security assessment platform for IPsec VPNs. It automatically converts raw PCAP traffic and gateway configurations into structured cryptographic evidence, stateful IKE analysis, flow behavioral intelligence, risk scores (0–100), and automated remediation guidance (`swanctl.conf` / Cisco IOS-XE).

---

## 📸 Interface Preview

| SOC Assessment Dashboard | Security Findings & Evidence | Remediation Diffs & Checklist |
| :---: | :---: | :---: |
| <img width="100%" alt="Dashboard" src="https://github.com/user-attachments/assets/0eaed9e9-522f-4ff2-94e8-18db0c22b37c" /> | <img width="100%" alt="Findings + Evidence" src="https://github.com/user-attachments/assets/c59cb207-e4c8-4788-93b7-b772ad56973b" /> | <img width="100%" alt="Remediation View" src="https://github.com/user-attachments/assets/cf9015a1-cefe-4faf-8562-8961a54036da" /> |

---

## ⚡ Core Capabilities & Observability Matrix

NetSentry AI preserves cryptographic boundaries (no payload decryption claimed) and maps findings to a rigorous Observability Taxonomy:

| Capability | Status | Observability | Details |
| :--- | :---: | :---: | :--- |
| **IKEv1 / IKEv2 Dissection** | **Implemented** | `OBSERVED` | Native raw IPv4 (`DLT_IPV4`), Ethernet, and Linux SLL parsing via Scapy / dpkt |
| **DH Group / Cipher Extraction** | **Implemented** | `OBSERVED` | Decoded from unencrypted `IKE_SA_INIT` and Main Mode proposals against RFC 8247 / 8221 |
| **IKE State Machine (FSM)** | **Implemented** | `OBSERVED` | Tracks exchange sequences, flags retransmissions, abnormal transitions, downgrade attacks |
| **ESP Traffic & Replay Analysis** | **Implemented** | `OBSERVED` | Correlates SPIs to IKE sessions; verifies 32-bit sequence numbers for replay protection |
| **14 Encrypted Flow Features** | **Implemented** | `OBSERVED` | Mathematical extraction: packet counts, directional bytes, inter-arrival variance, burst factor |
| **Behavioral Traffic Classifier** | **Implemented** | `INFERRED` | Multi-class Random Forest categorizing encrypted flows (Web, VoIP, Video, Bulk) |
| **Anomaly Detection & Explainability** | **Implemented** | `INFERRED` | Unsupervised Isolation Forest with Tree SHAP top-feature attributions |
| **Tunnel vs. Transport Mode** | **Implemented** | `INFERRED` | Inferred from gateway IP endpoint topology and MTU framing |
| **PFS in Encrypted Child SA** | **Policy-Bound** | `NOT OBSERVABLE` | Strictly marked `NOT OBSERVABLE` in passive captures without shared secrets |
| **Safe Remediation Engine** | **Implemented** | `REMEDIAL` | Syntactic configuration diffs (`swanctl.conf`, Cisco IOS-XE), pre-flight checks, rollback steps |
| **Dual PDF Audit Reports** | **Implemented** | `REPORTING` | Generates 1-2 page Executive Brief and comprehensive Technical Forensic Audit PDF |

---

## 🏗️ Architecture Pipeline

```text
 PCAP Upload / Capture (Ethernet, DLT_IPV4 raw, SLL)
                     │
                     ▼
         Packet Parser & Dissector (dpkt / Scapy)
                     │
                     ▼
        Session & Security Association Correlator
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
Stateful IKE FSM            Flow Feature Extraction (14D)
       │                           │
       ▼                           ▼
Deterministic RFC Rules    Behavioral ML & Isolation Forest
       │                           │
       └─────────────┬─────────────┘
                     ▼
       Evidence-Driven Findings Matrix (7 Columns)
                     │
                     ▼
        Risk Scoring Engine (0–100 Scale)
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
Interactive SOC Console    Safe Remediation Diffs & Dual PDFs
(React 18 + Tailwind)      (swanctl, Cisco, ReportLab)
```

---

## 🚀 Quick Start & Setup Instructions

### Prerequisites
* **Python 3.12+**
* **Node.js 18+** & **npm 9+**
* **Git**
* *(Optional)* **Docker & Docker Compose**

---

### Option 1: Docker Compose (Fastest)

Run the full stack with a single command:

```bash
docker compose up --build
```

* **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
* **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option 2: Local Manual Setup

#### Step 1: Clone Repository
```bash
git clone https://github.com/apjai03-vibecode/netsentry-ai.git
cd netsentry-ai
```

#### Step 2: Backend Setup
```bash
cd backend

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (Command Prompt):
.\venv\Scripts\activate.bat
# Linux / macOS:
source venv/bin/activate

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Start backend server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

* API will run at: `http://127.0.0.1:8000`
* Interactive API Documentation (Swagger): `http://127.0.0.1:8000/docs`
* Health Check: `http://127.0.0.1:8000/health`

#### Step 3: Frontend Setup
Open a new terminal window:
```bash
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

* Dashboard UI will run at: `http://localhost:3000`

---

### 🔑 Default Credentials

Sign in on the frontend dashboard with the pre-seeded analyst credentials:
* **Username**: `analyst`
* **Password**: `Password123!`

---

## 🧪 Testing & Verification

### Run Backend Pytest Suite (57 Tests)
With the backend virtual environment active:
```bash
cd backend
pytest tests -v
```
Expected output:
```text
============================= 57 passed in ~10s =============================
```

### Run Frontend Production Build Check
```bash
cd frontend
npm run build
```

---

## 📁 Repository Structure

```text
netsentry-ai/
├── backend/
│   ├── app/
│   │   ├── engines/           # Rule engine, FSM tracker, Threat matrix, Remediation
│   │   ├── ml/                # 14D flow features, Traffic classifier, Isolation Forest, SHAP
│   │   ├── parsers/           # IKEv1/v2 & ESP parser (Scapy/dpkt), Live capture stream
│   │   ├── reports/           # PDF Report generator (Executive Brief & Forensic Audit)
│   │   ├── routers/           # REST endpoints (auth, ingest, assessment, ml, testbed, traffic)
│   │   └── testbed/           # Synthetic traffic profiles & configuration generator
│   ├── tests/                 # 57 automated unit and integration tests
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/        # SOC console, ThreatMatrix, RemediationDiff, EvidenceDrawer
│   │   ├── pages/
│   │   └── services/          # API clients & auth interceptors
│   ├── package.json
│   └── vite.config.js
├── docker-compose.yml
└── README.md
```

---

## 🏆 Smart India Hackathon 2026

* **Problem Statement ID:** SIH26160
* **Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
* **Theme:** Cybersecurity & AI
* **Team Name:** Code craftss

### Team Members
| Name | Role / Domain |
| :--- | :--- |
| **Aswini V** | Backend & Protocol Engines |
| **Aparajitha J** | Machine Learning & Behavior Intelligence |
| **Karthika MP** | Frontend Engineering & SOC Console UI |
| **Karthika R** | Architecture & DevOps Pipeline |
| **Hema U** | Cryptographic Research & Documentation |
| **Gayathri D** | Technical Validation & Presentation |

---

## 📜 References & Standards

* **RFC 7296** — Internet Key Exchange Protocol Version 2 (IKEv2)
* **RFC 8247** — Cryptographic Algorithm Implementation Requirements for IKEv2
* **RFC 8221** — Cryptographic Algorithm Implementation Requirements for ESP & AH
* **RFC 4301 / 4303** — Security Architecture for IP & Encapsulating Security Payload (ESP)
* **NIST SP 800-77 Rev. 1** — Guide to IPsec VPNs
* **NIST SP 800-57 Part 1** — Recommendation for Key Management

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
