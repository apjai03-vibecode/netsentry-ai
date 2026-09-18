# NetSentry AI

**An AI-powered tool that checks if your VPN setup is secure.**

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Node](https://img.shields.io/badge/node-24-green)
![Tests](https://img.shields.io/badge/tests-44%20passing-brightgreen)

| | |
|---|---|
| **Problem Statement ID** | SIH26160 |
| **Problem Statement Title** | AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework |
| **Theme** | Cybersecurity & AI |
| **Event** | Smart India Hackathon 2026 |
| **Team** | Code Craft |

---

## What does this project do?

Upload a VPN packet capture (`.pcap`/`.pcapng`) or a VPN config file (like `swanctl.conf` or a Cisco config), and NetSentry AI will:

1. Read the file and pull out the technical details of the VPN handshake (encryption used, key exchange method, etc.)
2. Check those details against known security best practices
3. Use a machine learning model to catch anything unusual that the rules might miss
4. Give you a security score from 0 to 100, with a clear explanation of *why*
5. Suggest exactly what to change in your config to fix any problems
6. Let you download a PDF report of everything

Think of it as a security "health check" for VPN connections — you give it evidence of a VPN session, and it tells you how safe it actually is.

---

## Screenshots

<!-- Replace these with actual screenshots or a short GIF before submission -->
| Dashboard | Findings + Evidence | Remediation View |
|---|---|---|
| <img width="100%" alt="Dashboard" src="https://github.com/user-attachments/assets/0eaed9e9-522f-4ff2-94e8-18db0c22b37c" /> | <img width="100%" alt="Findings + Evidence" src="https://github.com/user-attachments/assets/c59cb207-e4c8-4788-93b7-b772ad56973b" /> | <img width="100%" alt="Remediation View" src="https://github.com/user-attachments/assets/cf9015a1-cefe-4faf-8562-8961a54036da" /> |
**[Watch the demo video](#)** _(add link once recorded)_

---

## How it works (in plain terms)

```
You upload a file
      │
      ▼
The file gets parsed (we extract the technical VPN details)
      │
      ▼
Four checks run at the same time:
  • Rule Engine       → checks against known security standards (RFCs)
  • Handshake Tracker → makes sure the VPN negotiation happened correctly
  • ML Model          → flags anything statistically unusual
  • ESP Monitor       → checks the encrypted data channel
      │
      ▼
All four results are combined into one risk score (0–100)
      │
      ▼
You see the score, the findings, and suggested fixes on the dashboard
(and can export it all as a PDF)
```

---

## Tech stack

| Part | What we used | Why |
|---|---|---|
| Frontend | React + Vite + Tailwind CSS | Fast, modern, easy to style |
| Backend | Python + FastAPI | Simple to write, great for APIs |
| Packet parsing | Scapy, DPKT | Standard tools for reading network traffic |
| Database | PostgreSQL (SQLite for local testing) | Stores findings and history |
| Background jobs | Redis + Celery | So file processing doesn't freeze the app |
| Machine learning | XGBoost + Isolation Forest | Catches known and unknown security issues |
| Explainability | SHAP | Shows *why* the model flagged something, not just that it did |
| Reports | ReportLab | Generates downloadable PDF summaries |

---

## Project folders — what's where

```
netsentry-ai/
├── backend/               → all the Python/FastAPI code
│   ├── app/
│   │   ├── parsers/       → reads the uploaded VPN files
│   │   ├── rules/         → the security rules (in a YAML file, easy to edit)
│   │   ├── engines/       → the actual checking logic (rules, handshake, scoring)
│   │   ├── ml/            → the machine learning models
│   │   ├── reports/       → PDF generation
│   │   └── routers/       → the API endpoints (upload, login, results, etc.)
│   └── tests/             → automated tests (44 passing)
├── frontend/              → the React dashboard you see in the browser
├── docker-compose.yml     → runs the whole project with one command
└── README.md              → you are here
```

---

## Getting it running

Before you start, copy the example environment file and fill in your own values:

```bash
cp .env.example .env
```

This sets your database URL, secret key, and Redis URL. Sensible defaults are provided for local development.

You have two options — pick whichever is easier for you.

### Option A: One command with Docker (recommended if you have Docker)

```bash
docker compose up --build
```

That's it. Once it's done:
- Dashboard: **http://localhost:3000**
- API docs: **http://localhost:8000/docs**

This starts everything for you — the database, the background worker, the backend, and the frontend.

### Option B: Run it manually (no Docker needed)

**1. Start the backend:**
```bash
cd backend
python -m venv venv

# Windows:
.\venv\Scripts\Activate.ps1
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Backend is now running at http://127.0.0.1:8000/docs

**2. Start the frontend (in a new terminal):**
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:3000 in your browser.

**3. Try it instantly:**
Click **"⚡ Test with Insecure Sample PCAP"** on the dashboard — this runs a full analysis on a sample file with no setup needed, so you can see the tool in action right away.

---

## Running the tests

```bash
cd backend
pytest tests -v
```

This runs 44 automated tests covering login/auth, file uploads, the rule/ML engines, and the scoring logic.

---

## How good is the machine learning model?

We tested the model on a set of VPN sessions to see how well it tells secure configs apart from insecure ones.

> **Note:** these numbers were measured on our own generated test data. We're actively testing against real-world VPN captures too, and will update these numbers as that testing continues — real-world traffic is messier than synthetic data, so we expect the numbers to shift once tested more broadly.

| Metric | What it means | Result |
|---|---|---|
| Accuracy | How often it got the right answer overall | High |
| Precision | When it says "this is vulnerable," how often it's right | High |
| Recall | Of all the actually-vulnerable configs, how many it caught | High |
| False Positive Rate | How often it wrongly flagged a secure config | Low |

We also use **SHAP** to explain every prediction — so instead of just saying "this is risky," it tells you *which specific factor* (e.g. weak encryption, missing forward secrecy) contributed most to that score.

---

## What makes this different from just running Wireshark manually

- **It's automated** — no manually reading packet dumps
- **It explains itself** — every finding comes with the evidence and the reasoning, not just a verdict
- **It suggests fixes** — you get a ready-to-use corrected config, not just a warning
- **It catches unknowns too** — the ML layer can flag unusual behavior even if it doesn't match a known bad pattern

---

## Main API endpoints

Full interactive docs are always available at `/docs` once the backend is running. Quick reference:

| Method | Endpoint | What it does |
|---|---|---|
| POST | `/api/auth/register` | Create a new account |
| POST | `/api/auth/login` | Log in and get a JWT token |
| GET | `/api/auth/me` | Get the logged-in user's details |
| POST | `/api/upload` | Upload a PCAP/PCAPNG or config file |
| GET | `/api/jobs/{job_id}` | Check the status of an upload/analysis job |
| GET | `/api/assessments/{job_id}` | Get the full risk assessment and findings |
| GET | `/api/ml/metrics` | View current ML model performance stats |

---

## Security & data handling

Since this tool processes network capture files that can contain sensitive data:

- Uploaded files are **encrypted at rest** (AES-256 via Fernet)
- Raw captures are **automatically deleted** after a configurable retention window — only the extracted metadata and findings are kept long-term
- All API access requires authentication (JWT), with role-based permissions (`analyst` / `admin`)
- File uploads are validated for type and size before processing, and rate-limited to prevent abuse

---

## Known limitations & what's next

We're upfront about what this version does and doesn't cover yet:

- Currently supports **IKEv1 and IKEv2** — other VPN protocols (WireGuard, OpenVPN, SSL VPN) are not yet supported
- ML model has been validated primarily on our own generated test dataset; broader testing against diverse real-world captures is ongoing
- No live/real-time traffic capture yet — currently works on uploaded files (pcap/config) only
- Planned next: SIEM/SOC tool integration, support for additional VPN protocols, and expanded real-world validation data

---

## Team

**Team Code Craft** — Smart India Hackathon 2026 — Problem Statement SIH26160

| Name | Role |
|---|---|
| Aswini V | Backend / API |
| Aparajitha J | ML / Data |
| Karthika MP | Frontend / Dashboard |
| Karthika R | Architecture / DevOps |
| Hema U | Research / Documentation |
| Gayathri D | Presentation ppt |

---

## License

MIT — see [LICENSE](./LICENSE) for details.
