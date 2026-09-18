# NetSentry AI

**An AI-powered tool that checks if your VPN setup is secure.**

Built for Smart India Hackathon 2026 (Problem Statement SIH26160) by Team Code Craft.

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

## License

MIT — see [LICENSE](./LICENSE) for details.

---

## Team

Team Code Craft — Smart India Hackathon 2026 — Problem Statement SIH26160
