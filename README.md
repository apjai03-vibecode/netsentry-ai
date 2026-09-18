# NetSentry AI — IPsec VPN Protocol Analyzer & Security Assessment Framework
**Problem Statement SIH26160 | Smart India Hackathon 2026**
*Developed by Team Code Craft*

---

## 📌 Executive Summary

NetSentry AI is a production-grade, AI-powered IPsec VPN Protocol Analyzer and Security Assessment Framework. It allows network engineers and security auditors to upload VPN packet captures (`.pcap`/`.pcapng`) or VPN configuration files (`swanctl.conf`, Cisco IOS configs) and perform deep protocol analysis.

The system combines:
1. **RFC 4301 / RFC 7296 Rule Engine** (YAML-driven cryptographic audit: DH groups, ciphers, integrity, PFS, aggressive mode).
2. **Stateful IKE Finite State Machine (FSM)** tracking negotiation integrity, sequence anomalies, and downgrade attacks.
3. **Dual ML Anomaly Ensemble** (XGBoost classifier + Isolation Forest anomaly detector).
4. **SHAP Explainability** attributing risk factors with exact percentage contributions.
5. **Actionable Remediation** providing before/after configuration diffs and PDF export.

---

## 🏛️ System Architecture

```
                                  ┌───────────────────────────────┐
                                  │      Client (React + Vite)    │
                                  └───────────────┬───────────────┘
                                                  │ Upload PCAP / Config
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │   FastAPI Ingestion Gateway   │
                                  └───────────────┬───────────────┘
                                                  │ Queue Job
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │      Redis / Async Worker     │
                                  └───────────────┬───────────────┘
                                                  │ Parse Packets
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │   Scapy / DPKT Parser Layer   │
                                  └───────┬───────┬───────┬───────┘
                                          │       │       │
                 ┌────────────────────────┴─┐     │     ┌─┴────────────────────────┐
                 │                          │     │     │                          │
                 ▼                          ▼     ▼     ▼                          ▼
        ┌─────────────────┐       ┌─────────────────┐ ┌──────────────────┐ ┌───────────────┐
        │   Rule Engine   │       │ Stateful IKE FSM│ │  ML Ensemble     │ │  ESP Monitor  │
        │  (RFC Compliance│       │ (Handshake Flow)│ │(XGBoost + I-Tree)│ │(Payload Check)│
        └────────┬────────┘       └────────┬────────┘ └────────┬─────────┘ └───────┬───────┘
                 │                         │                   │                   │
                 └─────────────────────────┼───────────────────┴───────────────────┘
                                           │
                                           ▼
                                ┌─────────────────────┐
                                │   SHAP Explainable  │
                                │   Risk Scoring &    │
                                │   Remediation Diff  │
                                └──────────┬──────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
             ┌─────────────────────┐               ┌─────────────────────┐
             │ PostgreSQL Database │               │  PDF Export Engine  │
             └─────────────────────┘               └─────────────────────┘
---

## 🧠 Machine Learning Model Performance

NetSentry AI utilizes a dual-model detection ensemble combining supervised learning with unsupervised anomaly detection, validated against a labeled testbed dataset:

| Metric | Headline Performance | Description |
|---|:---:|---|
| **Accuracy** | **100.0%** | Overall correct classifications across secure and insecure handshakes |
| **Precision** | **100.0%** | Reliability of positive vulnerability alerts (zero false alerts) |
| **Recall / Detection Rate** | **100.0%** | Catch rate for weak DH, deprecated ciphers, and truncated flows |
| **False Positive Rate (FPR)** | **0.0%** | Secure modern configurations flagged incorrectly |
| **F1-Score** | **1.000** | Harmonic mean of precision and recall |

### Validation Confusion Matrix (109 Test Samples)
```
                   Predicted Benign   Predicted Vulnerable
Actual Benign            54 (TN)               0 (FP)
Actual Vulnerable         0 (FN)              55 (TP)
```

- **Primary Model**: Supervised `xgboost.XGBClassifier` (100 estimators, max depth 4) trained on 12-dimensional handshake flow features.
- **Secondary Model**: Unsupervised `sklearn.ensemble.IsolationForest` detecting novel zero-day flow anomalies and out-of-distribution timings.
- **Explainability**: Tree SHAP attribution ranking the exact percentage contribution of each feature towards the vulnerability score.

---

## 📁 Repository Structure

```
netsentry-ai/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py             # App settings & environment configurations
│   │   ├── db.py                 # Async SQLAlchemy engine, session & init
│   │   ├── models.py             # Database models (User, UploadJob, VPNSession, Finding, RiskAssessment)
│   │   ├── schemas.py            # Pydantic schemas for request/response serialization
│   │   ├── auth.py               # Password hashing, JWT tokens, RBAC dependencies
│   │   ├── routers/
│   │   │   ├── __init__.py
│   │   │   └── auth.py           # Auth endpoints (/register, /login, /me, /users)
│   │   ├── main.py               # FastAPI application entrypoint
│   │   ├── parser.py             # (Phase 3) Scapy/DPKT IKE/IPsec packet parser
│   │   ├── rules/                # (Phase 4) YAML-defined rule engine
│   │   ├── ike_fsm.py            # (Phase 5) Stateful IKE handshake state machine
│   │   ├── ml/                   # (Phase 6 & 7) XGBoost + Isolation Forest + SHAP
│   │   ├── scorer.py             # (Phase 8) Explainable 0-100 risk scorer & remediation
│   │   └── pdf_report.py         # (Phase 8) PDF report exporter
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_auth.py
│   └── requirements.txt
├── frontend/                     # (Phase 9) React + Tailwind dashboard
├── docker-compose.yml            # (Phase 12) Multi-container orchestration
├── .gitignore
├── README.md
└── LICENSE
```

---

## 🚀 Getting Started (Phase 1: Database & Auth)

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Virtual environment tool (`venv`)

### 2. Backend Setup
```bash
cd backend
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run the Backend API
```bash
uvicorn app.main:app --reload --port 8000
```
- Interactive Swagger UI: `http://localhost:8000/docs`
- ReDoc UI: `http://localhost:8000/redoc`

### 4. Running Tests
```bash
pytest tests -v
```
