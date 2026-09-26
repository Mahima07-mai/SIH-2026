# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

A working **prototype** of an email threat-analysis pipeline: manual input →
parallel analyzers → evidence normalization → correlation/rules → advisory
local ML spam analysis → deterministic threat classification → entity graph →
proof chain → forensic report → interactive dashboard.

The content classifier is local and does not require an external API key.

---

## 1. Architecture at a glance

```
MANUAL EMAIL INPUT
        |
        v
INGESTION & PARSING            (app/utils/header_parser.py)
        |
        v
PARALLEL FEATURE EXTRACTION    (app/analyzers/*.py — 7 analyzers)
        |
        v
EVIDENCE NORMALIZATION         (app/schemas/evidence.py)
        |
        v
CORRELATION ENGINE             (app/correlation/{graph,rules,scoring}.py)
        |              \
        |          ML SPAM EVIDENCE (app/services/ml_service.py)
        |              /
        v
THREAT CLASSIFIER              (app/classifier/threat_classifier.py)  <- deterministic decision layer
        |
        v
CROSS-EMAIL CAMPAIGN ENGINE    (app/correlation/campaign.py)
        |
        v
REPORT + GRAPH ASSEMBLY        (app/reporting/*.py)
        |
        v
REACT DASHBOARD
```

**The one rule that matters most:** the ML model is an *advisory evidence
source*, not the only decision-maker. It produces a `SPAM_PROBABILITY`
finding with `fact_level: Inferred` and `reliability: Medium`. The final `PHISHING` / `BEC` / `MALWARE` /
`SPOOFING` / `SCAM` / `SPAM` / `BENIGN` verdict comes from
`classifier/threat_classifier.py`, a deterministic, fully-explainable
rule-based function that combines the model probability with hard technical
evidence (SPF/DKIM/DMARC, domain age, MIME mismatches, YARA hits, etc.)
using the same auditable weighted-rule mechanism throughout.

Every finding in the system is normalized into one canonical `Evidence`
shape with two **independent** axes:
- `fact_level`: `Observed` (directly obtained) / `Derived` (computed from
  observations) / `Inferred` (model interpretation)
- `reliability`: `High` / `Medium` / `Low`

A DMARC failure is `Observed` + `High`. An ML spam probability is
`Inferred` + `Medium`. These are never conflated.

---

## 2. Project structure

```
project/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app entrypoint
│   │   ├── config.py                Env-driven settings (no hardcoded secrets)
│   │   ├── pipeline.py              Orchestrates the full pipeline
│   │   ├── storage.py               In-memory store (swap for Postgres later)
│   │   ├── schemas/                 Pydantic models (Evidence, AnalyzeRequest, ...)
│   │   ├── utils/header_parser.py   Raw-header parsing (email stdlib)
│   │   ├── analyzers/               7 parallel feature extractors
│   │   ├── services/                ml_service, geo_service, whois_service
│   │   ├── correlation/             graph.py, rules.py, scoring.py, campaign.py
│   │   ├── classifier/              threat_classifier.py (deterministic)
│   │   ├── reporting/               proof_chain.py, limitations.py, pdf_report.py
│   │   └── api/                     analyze.py, reports.py
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── components/              InputForm, Dashboard, EntityGraphView, ...
│   │   ├── data/demoEmails.ts       5 demo scenarios
│   │   ├── services/api.ts
│   │   └── types/index.ts
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml
└── README.md   (this file)
```

---

## 3. Running it locally (without Docker)

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# The local multiclass ML model needs no external API key.
uvicorn app.main:app --reload --port 8000
```

Some optional dependencies (`python-magic`/libmagic, `oletools`, `yara-python`,
`python-whois`) may need extra system packages or may simply fail to import
on some platforms — this is by design: every analyzer degrades to an
explicit `"unavailable"` status rather than crashing the pipeline. Install
`libmagic1` (Linux: `apt-get install libmagic1`, Mac: `brew install libmagic`)
for the best attachment MIME detection.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173`. The Vite dev server proxies `/api/*` to
`http://localhost:8000` (see `vite.config.ts`).

### With Docker Compose

```bash
cp backend/.env.example backend/.env   # then edit backend/.env
docker compose up --build
```

---

## 4. Using the app

1. Open the frontend. Either fill in the structured header fields, or check
   "Use raw headers instead of fields" and paste a raw RFC-5322 header
   block — it's parsed automatically.
2. Paste the email body (plain text and/or HTML).
3. Paste any URLs (URLs found in the body are also auto-extracted).
4. Drag-and-drop attachments, or click the upload area.
5. Or just click one of the **Load Demo** buttons (Benign, Phishing, BEC,
   Malware, Spoofing) to see the pipeline run against pre-built scenarios.
6. Click **ANALYZE EMAIL**.
7. Explore the 13 dashboard tabs: Overview, Sender, Authentication,
   Infrastructure, Domains, URLs, Attachments, NLP, Evidence, Proof Chain,
   Entity Graph, Campaigns, Limitations.
8. Click **Export PDF** for a forensic report.
9. Analyze a second demo email that shares an IP/domain/hash with the first
   to see the **Campaigns** tab populate with a cross-email relationship.

---

## 5. What's real vs. what's a documented gap (by design, for a prototype)

| Capability | Status |
|---|---|
| Header/identity mismatch detection | Real, deterministic |
| SPF/DKIM/DMARC parsing | Real, parses `Authentication-Results` |
| IP extraction from Received headers | Real |
| IP geolocation | Real if `IPINFO_TOKEN` is set, else explicit "unavailable" |
| DNS records | Real (dnspython) |
| WHOIS / domain age | Real (python-whois), network/rate-limit dependent |
| Punycode / brand-similarity heuristics | Real, lightweight heuristic — not a commercial brand-protection engine |
| URL redirect chain / TLS cert check | Real, bounded by timeout/redirect/size limits, nothing executed |
| URL reputation feed | **Not wired in** — returns `"unavailable"`; stub is `services/reputation_service.py` naming convention, extend as needed |
| Attachment hashing (SHA-256/SHA-1) | Real |
| MIME detection | Real via python-magic, falls back to signature bytes if libmagic absent |
| Macro detection | Real via oletools if installed, else "unavailable" |
| YARA scanning | Real via yara-python with an illustrative 2-rule set — **not a production ruleset** |
| Sandbox detonation | **Not implemented** — always reports `sandbox_status: NOT_AVAILABLE`; files are never executed |
| ML threat content analysis | Local multiclass TF-IDF + logistic regression; supports benign, spam, phishing, BEC, spoofing, and malware |
| Correlation rules (10 rules) | Real, deterministic, weighted, fully explainable |
| Threat classification | Real, deterministic decision tree — **not** the LLM |
| Entity graph | Real, built with NetworkX, rendered with React Flow |
| Proof chain | Real, generated from actually-matched rules (never hard-coded) |
| Cross-email campaign detection | Real, but only within the current server process's in-memory store (resets on restart) |
| PDF report | Real, via ReportLab |
| Persistent storage | In-memory only in this prototype; `storage.py` is written so swapping in SQLAlchemy + Postgres later doesn't require touching any analyzer/pipeline code |

---

## 6. Extending toward production

### Prepare the larger text model

From `backend/`, run:

```powershell
python scripts/prepare_datasets.py --download
```

This downloads the official SpamAssassin public corpus and Nazario phishing
corpus, extracts text only, combines them with `archive/email_spam.csv` and
the redacted seed examples in `backend/data/threat_seed.csv`, and writes the
ignored local file `backend/data/threat_training.csv`. The backend trains its
multiclass model from that file at startup. Raw downloaded mail remains under
`backend/data/raw/` and is ignored by git.

The current normalized training set contains 1,268 rows: 531 spam, 314
benign, 408 phishing, and 5 each for BEC, spoofing, and malware. The three
small categories use safe redacted seed examples because public BEC, spoofing,
and malware corpora commonly contain private business mail or live malicious
attachments. Add properly licensed, sanitized labeled data for those classes
before treating their metrics as production-quality.

- Swap `app/storage.py` for real SQLAlchemy models against `DATABASE_URL`
  (Postgres) — the shape already mirrors the spec's table design.
- Wire a real URL/domain reputation provider into
  `services/reputation_service.py` (e.g. Google Safe Browsing, VirusTotal).
- Replace the illustrative YARA ruleset in `attachment_analyzer.py` with a
  maintained, licensed ruleset.
- Add a dynamic sandbox (e.g. CAPEv2, Cuckoo) behind the same
  `sandbox_status` contract.
- Move `pipeline.run_analysis` into a FastAPI `BackgroundTask` (or Celery
  worker) once analyzers start doing real network I/O at scale, and have
  the frontend poll `GET /api/emails/{id}` for progress instead of
  blocking on `POST /api/analyze`.
- Swap the NetworkX entity graph for Neo4j if you need persistent,
  queryable graph storage across large email volumes.

---

## 7. Forensic principles this prototype enforces

- Never claims a physical attacker location — only where *sending
  infrastructure* geolocates.
- Never lets an authentication failure alone stand in for "proof of
  spoofing."
- Never lets the LLM's output become the final verdict.
- Every report includes a "What We Cannot Know" section, generated only
  from evidence actually present in that analysis.
- Failed/unavailable external integrations are always labeled
  `"unavailable"` — never silently replaced with a fabricated value.
