# AETHER — AI-Enabled Malware Analysis & Threat Attribution

AETHER ingests cross-format artifacts (PDF · JavaScript · Images · Archives · binaries),
performs **real static malware detection** on the actual file bytes, extracts IoCs and
MITRE ATT&CK TTPs, explains every verdict, and correlates findings to threat actors —
presented through a SOC-style operations console.

```
┌────────────┐   HTTP    ┌─────────────────┐   HTTP    ┌──────────────────────┐
│  Frontend  │ ───────►  │  API Gateway    │ ───────►  │   AI/ML Worker       │
│ React/Vite │           │  Node + Express │           │  Python + FastAPI    │
│  :5173     │ ◄───────  │  :4000          │ ◄───────  │  :8000               │
└────────────┘           └────────┬────────┘           │  • static detect     │
                                  │                     │    engine (real)     │
                     ┌────────────┴────────────┐        │  • external LLM      │
                     ▼                          ▼        │  • pycti → OpenCTI   │
               MongoDB :27017             Neo4j :7687    └──────────┬───────────┘
            (AnalysisJobs)          (threat graph)                  │ (optional)
                                                                    ▼
                                                   OpenCTI stack :8080 (attribution)
                                            Redis · Elasticsearch · MinIO · RabbitMQ
```

> **Resilient by design.** If MongoDB/Neo4j are unreachable the gateway falls back to
> pre-seeded in-memory stores, so the stack runs end-to-end even without databases
> (data just won't persist).

---

## What it actually does

Detection runs on the **real bytes** of each upload — no trained model or internet required:

- **Signature engine** — weighted, MITRE-mapped rules (EICAR, embedded PE/MZ, encoded/
  hidden PowerShell, download-and-execute, JS obfuscation, process-injection APIs,
  registry persistence, LOLBins, VBA macros, clipboard/ClickFix) — `ml-worker/app/detect/signatures.py`
- **Format analyzers** — PDF (`/JavaScript`, `/Launch`, `/EmbeddedFile`…), script heuristics,
  archive inspection (nested EXE, double-extension, encrypted, zip-bomb), image
  steganography/polyglot detection — `ml-worker/app/detect/formats.py`
- **Forensics** — real SHA-256/SHA-1/MD5 hashes + Shannon entropy (packing detection)
- **IoC extraction** — regex over content (IPs, domains, URLs, hashes, registry keys,
  paths), de-noised and defanged — `ml-worker/app/detect/iocs.py`
- **Risk verdict** — noisy-OR over all fired signals → `benign | suspicious | malicious`
- **Explainability** — SHAP/LIME-style charts plotting the **real detection signals**
  and their weights (the "why")

> **Scope / honesty:** this is real **signature + heuristic static detection** (the class
> used by many AV/triage front-ends). It is **not** a trained ML classifier and **not** a
> dynamic sandbox — it does not execute samples, and novel malware that avoids all known
> patterns can evade it. Use for research/education and triage, not as a production AV.

---

## Integrations

| Integration | Status | Purpose | Enable with |
|---|---|---|---|
| **Static detection engine** | ✅ Built-in, always on | Real content-based malware detection | nothing — works offline |
| **Trained ML classifier** (your model) | ⚙️ Optional, **toggleable** | Your model's score is ensembled into the verdict | mount model + `INSTALL_ML=true` + UI toggle |
| **External LLM** (OpenAI-compatible) | ⚙️ Optional, **toggleable** | Enriches IoC/TTP extraction & summaries on obfuscated artifacts | `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` |
| **OpenCTI + pycti** (STIX2) | ⚙️ Optional | Pushes IoCs/TTPs for automated actor/campaign attribution (MITRE connector) | `--profile opencti` + `OPENCTI_ENABLED=true` |
| **MongoDB** | ✅ Default | Persists analysis jobs | bundled in compose |
| **Neo4j** | ✅ Default | Threat-correlation graph | bundled in compose |

The external LLM works against **any** OpenAI-compatible endpoint — OpenAI, a self-hosted
vLLM/LiteLLM gateway, or Anthropic's OpenAI-compat endpoint. There is **no local Ollama** —
LLM processing is routed entirely through the external API.

### Choosing & toggling AI engines (UI)
Open **AI Engines** in the sidebar to pick which AI systems power detection and turn each
on/off **live, without a restart**:

- **Static Engine** — always on (cannot be disabled).
- **Trained ML Classifier** — your model; available once mounted + built with ML deps.
- **External LLM** — available once an API key is configured.

Each analysis is tagged with the engines that produced it (e.g. `static`, `static+ml`,
`static+ml+llm`), shown as chips on the verdict. Toggles are also scriptable via the API:
```bash
curl http://localhost:4000/api/v1/ai-config                              # list engines
curl -X POST http://localhost:4000/api/v1/ai-config \
     -H 'Content-Type: application/json' -d '{"ml_enabled":true,"llm_enabled":false}'
```

---

## Requirements

**Prerequisite (all tiers):** Docker + Docker Compose v2 (Docker Desktop or Docker Engine).
No host install of Node / Python / Mongo / Neo4j is needed — everything is containerized.

| Tier | RAM (free) | Disk | Internet | Notes |
|---|---|---|---|---|
| **Core app** (full detection) | ~3–4 GB | ~3 GB | not required | frontend + gateway + worker + Mongo + Neo4j |
| **+ External LLM** | +~0 GB | — | **required** | a reachable OpenAI-compatible endpoint + key |
| **+ OpenCTI** | **~8 GB+** | ~8–10 GB | not required | adds Redis/Elasticsearch/MinIO/RabbitMQ/OpenCTI |

**Ports that must be free:** `5173` (UI), `4000` (gateway), `8000` (worker),
`27017` (Mongo), `7474` & `7687` (Neo4j); with OpenCTI also `8080`.

---

## Run the application

### Tier 1 — Core app (this is all you need for malware detection)
```bash
cd AETHER-CTRG
cp .env.example .env          # one-time
docker compose up -d --build
```
Open **http://localhost:5173**. Runs fully **offline, no API keys**. First boot waits for
the DB health checks, seeds mock graph/actor data, then comes online.

| Service | URL |
|---|---|
| Frontend (SOC console) | http://localhost:5173 |
| API Gateway | http://localhost:4000/api/v1 |
| AI/ML Worker | http://localhost:8000 (`/docs` for Swagger) |
| Neo4j browser | http://localhost:7474 (`neo4j` / value of `NEO4J_PASSWORD`) |

Tear down with `docker compose down` (add `-v` to also drop DB volumes).

### Tier 2 — Add external LLM enrichment (optional)
Edit [.env](.env):
```bash
AI_API_KEY=sk-...                       # your provider key
AI_BASE_URL=https://api.openai.com/v1   # or any OpenAI-compatible gateway
AI_MODEL=gpt-4o-mini
```
then apply to the worker only:
```bash
docker compose up -d ml-worker
```
Ingest a new sample → the Analysis view badge reads **Static + LLM**.

### Tier 3 — Add OpenCTI attribution (optional, ~8 GB RAM)
```bash
docker compose --profile opencti up -d --build
```
Wait for the platform at **http://localhost:8080** (login `OPENCTI_ADMIN_EMAIL` /
`OPENCTI_ADMIN_PASSWORD`) and let the MITRE connector seed. Then in [.env](.env):
```bash
OPENCTI_ENABLED=true
OPENCTI_TOKEN=<same value as OPENCTI_ADMIN_TOKEN>
```
and restart the worker: `docker compose up -d ml-worker`. Each analysis then pushes
Indicators + Attack-Patterns + a Report into OpenCTI via pycti.

### Tier 4 — Plug in YOUR trained model (optional)

Train a model on a malware dataset, then wire it in as the **ML classifier** engine. Its
score is **ensembled** with the static engine (definitive signature hits are preserved;
the model raises the score on what signatures miss).

**1. Export your model** into a folder — either:
- a HuggingFace `AutoModelForSequenceClassification` (a fine-tuned transformer/LLM with a
  classification head: `config.json`, `model.safetensors`, tokenizer files), or
- an exported **ONNX** model (`model.onnx` + tokenizer) for a smaller/faster CPU footprint.

**2. Mount it** under `ml-worker/models/` (git-ignored):
```
ml-worker/models/malware-clf/
├── config.json
├── model.safetensors        # or model.onnx
└── tokenizer.json …
```

**3. Configure** in [.env](.env):
```bash
INSTALL_ML=true                       # build the worker with torch/transformers
ML_CLASSIFIER_ENABLED=true            # default the engine on (also toggleable in UI)
CLASSIFIER_PATH=/models/malware-clf   # path INSIDE the container
CLASSIFIER_NAME=my-malware-clf-v1
CLASSIFIER_BACKEND=hf                 # hf | onnx
CLASSIFIER_MALICIOUS_INDEX=1          # which output index means "malicious"
CLASSIFIER_THRESHOLD=0.5
```

**4. Build with ML deps & restart** the worker:
```bash
INSTALL_ML=true docker compose build ml-worker
docker compose up -d ml-worker
```

**5. Verify** — the **AI Engines** page shows *ML Classifier → Enabled*; new analyses are
tagged `static+ml` and the model score appears as the top feature in the SHAP chart.

> **Accuracy is in the preprocessing.** Inference features **must** match how you trained.
> The default `_features()` in `ml-worker/app/models/classifier.py` feeds the decoded
> content as text — edit it if your model expects byte/PE/image features. Also confirm
> `CLASSIFIER_MALICIOUS_INDEX` and calibrate `CLASSIFIER_THRESHOLD` from your PR curve to
> hit your target false-positive rate. For best results, route per `file_type` to
> specialized models. Turn the engine off anytime from the **AI Engines** page.

#### A fine-tuned *generative* LLM instead?
If you fine-tuned a generative LLM (not a classifier head), **serve it** OpenAI-compatible
(vLLM / TGI / llama.cpp) and point the LLM engine at it — no code change:
```bash
AI_API_KEY=...   AI_BASE_URL=http://your-llm-host:8000/v1   AI_MODEL=my-finetuned-llm
```
It then enriches IoC/TTP extraction (badge `static+llm`). For the malicious/benign
*verdict*, the classifier route above is far more accurate than a generative model.

### Using it
Drag a file into **Ingestion** → watch **Analysis & XAI** auto-update (verdict ring,
detection signals, IoCs, ATT&CK coverage, stego, FAISS similarity, SHAP/LIME) → submit
analyst **feedback** → pivot into the **Threat Graph**. Choose engines under **AI Engines**.

Quick CLI smoke test (EICAR — a harmless industry-standard AV test file):
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
curl -s -F file=@/tmp/eicar.com -F sandbox_mode=Immediate http://localhost:4000/api/v1/ingest
```

---

## Local dev (without rebuilding containers)

```bash
# datastores only
docker compose up -d mongo neo4j

# worker
cd ml-worker && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && cp .env.example .env
uvicorn main:app --reload --port 8000

# gateway
cd backend && npm install && cp .env.example .env
npm run seed && npm run dev          # :4000

# frontend
cd frontend && npm install && cp .env.example .env
npm run dev                           # :5173
```

---

## API (gateway, prefix `/api/v1`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/ingest` | Upload file → detect type → YARA pre-scan → job_id (202) |
| GET | `/analysis/:id` | Verdict + signals + features + IoCs + TTPs + XAI |
| GET | `/analysis` | Recent detections (dashboard feed) |
| GET | `/threat-graph/:id` | Correlation subgraph (nodes/edges) |
| POST | `/feedback` | Analyst correction (self-learning loop) |
| GET | `/ai-config` | Which AI engines are available + enabled |
| POST | `/ai-config` | Toggle `ml_enabled` / `llm_enabled` live |
| GET | `/health` | Gateway + Mongo + Neo4j + worker status |

Worker (`:8000`): `POST /analyze`, `GET/POST /config`, `GET /health`, `GET /docs`.

---

## Environment variables (key ones)

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `AI_API_KEY` | worker | _(empty)_ | external LLM key; empty ⇒ LLM engine unavailable |
| `AI_BASE_URL` | worker | _(empty)_ | OpenAI-compatible endpoint |
| `AI_MODEL` | worker | `gpt-4o-mini` | model id |
| `INSTALL_ML` | build | `false` | bake torch/transformers into the image |
| `ML_CLASSIFIER_ENABLED` | worker | `false` | default the ML engine on (also UI-toggleable) |
| `CLASSIFIER_PATH` | worker | _(empty)_ | container path to your model dir |
| `CLASSIFIER_NAME` / `CLASSIFIER_BACKEND` | worker | `Trained ML Classifier` / `hf` | display name; `hf` or `onnx` |
| `CLASSIFIER_MALICIOUS_INDEX` / `CLASSIFIER_THRESHOLD` | worker | `1` / `0.5` | malicious output index; decision threshold |
| `OPENCTI_ENABLED` | worker | `false` | turn on the STIX2 push |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | worker | `http://opencti:8080` / _(empty)_ | OpenCTI target + token |
| `MONGO_PASSWORD` / `NEO4J_PASSWORD` | compose | `aether_dev_pw` | DB credentials |
| `OPENCTI_ADMIN_*`, `MINIO_*`, `RABBITMQ_*` | compose | see `.env.example` | OpenCTI stack creds (profile only) |

---

## What's real vs. lightweight

| Component | Status | File |
|---|---|---|
| Static detection engine (signatures, formats, IoCs, entropy, verdict, XAI) | ✅ **Real** | `ml-worker/app/detect/` |
| Trained ML classifier (your model, ensembled) | ✅ Real (when mounted + enabled) | `ml-worker/app/models/classifier.py` |
| AI-engine selection / live toggles | ✅ Real | `ml-worker/app/config_state.py`, `routes/config.py` |
| External LLM IoC/TTP enrichment | ✅ Real (when configured) | `ml-worker/app/models/llm.py` |
| OpenCTI STIX2 push | ✅ Real (when enabled) | `ml-worker/app/integrations/opencti.py` |
| Image / text embeddings, FAISS neighbors | ⚠️ Lightweight context | `ml-worker/app/models/`, `pipeline/clustering.py` |
| File-type detection, YARA pre-scan | ⚠️ Heuristic / mock | `backend/src/services/` |
| Threat actor attribution | ⚠️ Heuristic (+ OpenCTI when enabled) | `backend/src/services/analysisService.js` |

**Next upgrades:** real `yara-python` rule sets, a trained ML classifier (EMBER/PE
features, CNN-LSTM) for zero-day coverage, and dynamic sandbox detonation — each slots in
behind the existing interfaces.

> ⚠️ Research / education use only. Detonate real malware only in isolated environments.
