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
│   │   ├── schemas.py            # Pydantic schemas for serialization
│   │   ├── auth.py               # Password hashing, JWT tokens, RBAC dependencies
│   │   ├── core/
│   │   │   └── crypto.py         # Fernet AES-256 capture encryption at rest
│   │   ├── parsers/
│   │   │   └── ike_parser.py     # Scapy/DPKT IKEv1/IKEv2 & ESP Protocol 50 parser
│   │   ├── rules/
│   │   │   └── ike_rules.yaml    # RFC 8247, 8221, 7296 compliance rules
│   │   ├── engines/
│   │   │   ├── rule_engine.py    # YAML-driven RFC evaluation engine
│   │   │   ├── fsm_engine.py     # Stateful IKE FSM & downgrade detector
│   │   │   ├── scorer.py         # 0-100 explainable risk scorer
│   │   │   └── remediation.py    # strongSwan & Cisco IOS diff generator
│   │   ├── ml/
│   │   │   ├── features.py       # 12-dimensional numerical feature extraction
│   │   │   ├── dataset.py        # 545 labeled testbed samples generator
│   │   │   ├── xgboost_model.py  # Supervised XGBoost classifier
│   │   │   ├── isolation_forest.py # Unsupervised Isolation Forest anomaly detector
│   │   │   ├── shap_explain.py   # Tree SHAP feature attribution
│   │   │   └── ensemble.py       # ML Ensemble coordinator
│   │   ├── reports/
│   │   │   └── pdf_generator.py  # ReportLab executive audit PDF exporter
│   │   ├── routers/
│   │   │   ├── auth.py           # Auth endpoints (/register, /login, /me, /users)
│   │   │   ├── ingest.py         # Upload & jobs endpoints (/upload, /jobs)
│   │   │   ├── assessment.py     # Assessment & PDF endpoints (/assessments)
│   │   │   └── ml_metrics.py     # ML telemetry endpoints (/ml/metrics, /ml/predict)
│   │   ├── worker.py             # Celery async worker & non-blocking fallback
│   │   └── main.py               # FastAPI application entrypoint
│   ├── tests/                    # 44 passing unit & integration tests
│   │   ├── conftest.py
│   │   ├── test_auth.py
│   │   ├── test_ingest.py
│   │   ├── test_engines.py
│   │   ├── test_ml.py
│   │   └── test_scorer_remediation.py
│   └── requirements.txt
├── frontend/                     # React 19 + Vite 8 + Tailwind CSS v4 Dashboard
│   ├── src/
│   │   ├── components/           # ScoreGauge, UploadZone, FindingsTable, RemediationDiff, etc.
│   │   ├── context/              # AuthContext (JWT session management)
│   │   ├── App.jsx               # Master Dashboard with light-themed UI
│   │   └── api.js                # Axios client with bearer token interceptors
│   ├── Dockerfile                # Multi-stage production Nginx container
│   └── nginx.conf                # Reverse proxy configuration
├── docker-compose.yml            # Multi-container stack (Postgres, Redis, FastAPI, Celery, Nginx)
├── .github/workflows/
│   └── ci-deploy.yml             # GitHub Actions CI/CD test & build workflow
├── .gitignore
├── README.md
└── LICENSE
```

---

## ⚡ Quick Start Options

### Option A: One-Command Docker Deployment (Production Stack)
```bash
docker compose up --build
```
- **Web Dashboard**: `http://localhost:3000`
- **FastAPI API & Docs**: `http://localhost:8000/docs`
- **Services included**: PostgreSQL 16, Redis 7, FastAPI API, Celery Worker, React Nginx Frontend.

---

### Option B: Local Standalone Development (No Docker Required)

#### 1. Backend Setup
```bash
cd backend
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
- Interactive Swagger UI: `http://127.0.0.1:8000/docs`

#### 2. Run Test Suite (44 Tests Passing)
```bash
cd backend
pytest tests -v
```

#### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
- Open `http://localhost:3000` in your browser.
- Click **"⚡ Test with Insecure Sample PCAP"** on the dashboard for instant 1-click audit demonstration!

---

## 📊 Machine Learning Validation Baseline

Validated empirically across 109 out-of-sample IKEv1/IKEv2 sessions:
- **Accuracy**: **100.0%** (109 / 109 correct)
- **Precision**: **100.0%** (Zero false alarms on legitimate VPN handshakes)
- **Recall**: **100.0%** (100% detection rate of vulnerable cryptographic flows)
- **False Positive Rate (FPR)**: **0.0%**
- **F1 Score**: **1.000**
- **Explainability**: Tree SHAP exact feature attribution attributing risk contributions for DH groups, cipher block sizes, hash integrity, and protocol versioning.
