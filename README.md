# AETHER — AI-Enabled Malware Analysis & Threat Attribution

AETHER ingests cross-format artifacts (PDF · JavaScript · Images · Archives · binaries),
performs **real static malware detection** on the actual file bytes, runs **real AI models**
(CodeBERT/ResNet embeddings, CLIP steganography, FAISS similarity, a HuggingFace classifier,
SHAP/LIME explainability), extracts IoCs and MITRE ATT&CK TTPs, and correlates findings to
threat actors via **external OSINT** — presented through a SOC-style operations console.

```
┌────────────┐   HTTP    ┌─────────────────┐   HTTP    ┌──────────────────────────┐
│  Frontend  │ ───────►  │  API Gateway    │ ───────►  │   AI/ML Worker  :8000    │
│ React/Vite │           │  Node + Express │           │  Python + FastAPI        │
│  :5173     │ ◄───────  │  :4000          │ ◄───────  │  • static detect (real)  │
└────────────┘           └────────┬────────┘           │  • CodeBERT/ResNet emb.  │
                                  │                     │  • CLIP+LSB stego        │
                                  │                     │  • FAISS/UMAP clustering │
                                  │                     │  • SHAP/LIME XAI         │
                                  │                     │  • HF classifier (ensb.) │
                     ┌────────────┴────────────┐        │  • external LLM          │
                     ▼                          ▼        │  • OSINT + attribution   │
               MongoDB :27017             Neo4j :7687    │  • pycti → OpenCTI       │
            (AnalysisJobs)          (threat graph)       └──────────┬───────────────┘
                                                                    │ (optional)
                                                                    ▼
                                                   OpenCTI stack :8080 (attribution)
                                            Redis · Elasticsearch · MinIO · RabbitMQ
```

> **Resilient by design.** Every AI component degrades to a deterministic mock/static
> fallback when its dependency or key is absent, and the gateway falls back to pre-seeded
> in-memory stores if MongoDB/Neo4j are unreachable — so the stack always runs end-to-end
> and returns the identical response shape (data just won't persist).

---

## What it actually does

**Layer 1 — static detection** on the **real bytes** of each upload (no model or internet required):

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

**Layer 2 — real AI models** (active when built with the ML extras; otherwise each falls back to a mock):

- **Behavioral embeddings** — CodeBERT (`microsoft/codebert-base`, 768-d) for scripts/text,
  ResNet-50 (torchvision, 2048-d) for images — `ml-worker/app/models/*_embedding.py`
- **Steganography (CLIP + LSB + LLM)** — CLIP ViT-B/32 scores hidden-data prompts, an LSB
  bit-plane extractor recovers payloads, and the LLM decodes them — `ml-worker/app/models/stego_detector.py`
- **Similarity clustering** — FAISS `IndexFlatIP` nearest-neighbors + UMAP 2-D projection +
  KMeans over a labeled reference corpus, per-modality — `ml-worker/app/pipeline/clustering.py`
- **Explainability (SHAP + LIME)** — genuine token Shapley values + LIME local importances
  over the classifier (Deep mode); static signal-attribution otherwise — `ml-worker/app/pipeline/xai.py`
- **Trained classifier** — a HuggingFace sequence classifier (auto-downloads) whose score is
  **ensembled** into the verdict — `ml-worker/app/models/classifier.py`

**Layer 3 — enrichment & attribution:**

- **External LLM** — IoC/TTP extraction + summaries via any OpenAI-compatible endpoint — `ml-worker/app/models/llm.py`
- **OSINT** — AbuseIPDB + AlienVault OTX + VirusTotal reputation, aggregated into a real
  **threat-actor attribution** with confidence + rationale — `ml-worker/app/intel/osint.py`

> **Scope / honesty:** Layer 1 is real **signature + heuristic static detection**; Layer 2 adds
> real **pretrained** models (embeddings, CLIP, FAISS, SHAP/LIME) and an **ensembled** classifier.
> It is **not** a dynamic sandbox — it does not execute samples — and the bundled classifier is a
> general phishing/text model (swap in your own malware-trained weights via `CLASSIFIER_PATH`).
> Novel malware that avoids all known patterns can still evade it. Use for research/education and
> triage, not as a production AV.

---

## Integrations

| Integration | Status | Purpose | Enable with |
|---|---|---|---|
| **Static detection engine** | ✅ Built-in, always on | Real content-based malware detection | nothing — works offline |
| **Real embeddings / CLIP / FAISS / SHAP-LIME** | ✅ Real when built with ML extras | CodeBERT+ResNet embeddings, CLIP+LSB stego, FAISS clustering, SHAP/LIME XAI | `INSTALL_ML=true` build (auto-downloads weights) |
| **Trained ML classifier** | ✅ Real, **toggleable** (auto-downloads) | A HF classifier's score is ensembled into the verdict | `INSTALL_ML=true` + `CLASSIFIER_PATH` (defaults to a real HF model) + UI toggle |
| **External LLM** (OpenAI-compatible) | ⚙️ Optional, **toggleable** | Enriches IoC/TTP extraction, summaries, stego decode | `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` |
| **OSINT** (AbuseIPDB · OTX · VirusTotal) | ⚙️ Optional, **toggleable** | IoC reputation + real threat-actor attribution | any of `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `VT_API_KEY` |
| **OpenCTI + pycti** (STIX2) | ⚙️ Optional | Pushes IoCs/TTPs for automated actor/campaign attribution (MITRE connector) | `--profile opencti` + `OPENCTI_ENABLED=true` |
| **MongoDB** | ✅ Default | Persists analysis jobs | bundled in compose |
| **Neo4j** | ✅ Default | Threat-correlation graph (with OSINT abuse scores) | bundled in compose |

The external LLM works against **any** OpenAI-compatible endpoint — OpenAI, a self-hosted
vLLM/LiteLLM gateway, or Anthropic's OpenAI-compat endpoint. There is **no local Ollama** —
LLM processing is routed entirely through the external API. The embeddings/CLIP/classifier
weights are **pretrained and auto-downloaded** on first use (cached on a Docker volume).

### Choosing & toggling AI engines (UI)
Open **AI Engines** in the sidebar to pick which AI systems power detection and turn each
on/off **live, without a restart**:

- **Static Engine** — always on (cannot be disabled). Real embeddings/CLIP/FAISS/XAI ride along when the ML extras are installed.
- **Trained ML Classifier** — available once built with ML deps; auto-downloads its weights.
- **External LLM** — available once an API key is configured.
- **OSINT** — available once any AbuseIPDB/OTX/VirusTotal key is set; drives actor attribution.

Each analysis is tagged with the engines that produced it (e.g. `static`, `static+ml`,
`static+ml+llm+osint`), shown as chips on the verdict. Toggles are also scriptable via the API:
```bash
curl http://localhost:4000/api/v1/ai-config                              # list engines
curl -X POST http://localhost:4000/api/v1/ai-config \
     -H 'Content-Type: application/json' -d '{"ml_enabled":true,"llm_enabled":false,"osint_enabled":true}'
```

---

## Requirements

**Prerequisite (all tiers):** Docker + Docker Compose v2 (Docker Desktop or Docker Engine).
No host install of Node / Python / Mongo / Neo4j is needed — everything is containerized.

| Tier | RAM (free) | Disk | Internet | Notes |
|---|---|---|---|---|
| **Lite** (`INSTALL_ML=false`) | ~3–4 GB | ~3 GB | not required | real static engine; mock embeddings/CLIP/FAISS; no classifier |
| **Real models** (`INSTALL_ML=true`) | ~6–8 GB | ~8–12 GB | first run (weights) | CodeBERT/ResNet/CLIP/FAISS/SHAP + classifier; **GPU optional** |
| **+ External LLM / OSINT** | +~0 GB | — | **required** | reachable OpenAI-compatible endpoint + key; OSINT provider keys |
| **+ OpenCTI** | **~8 GB+** | ~8–10 GB | not required | adds Redis/Elasticsearch/MinIO/RabbitMQ/OpenCTI |

> **GPU vs CPU.** The real-model image runs on **CPU anywhere** (Apple-Silicon/Intel Mac,
> Linux, Windows) — just slower. For GPU acceleration use an **NVIDIA host** (with
> `nvidia-container-toolkit`) and add the GPU override (below). `ML_DEVICE=auto` uses the GPU
> when present and falls back to CPU otherwise. The classifier's default weights (bert-large,
> ~1.3 GB) are RAM-heavy; on an 8 GB machine keep `ML_CLASSIFIER_ENABLED=false` (embeddings/
> CLIP/FAISS still run) or point `CLASSIFIER_PATH` at a smaller model.

**Ports that must be free:** `5173` (UI), `4000` (gateway), `8000` (worker),
`27017` (Mongo), `7474` & `7687` (Neo4j); with OpenCTI also `8080`.

---

## Run the application

### Tier 1 — Core app (real models, CPU)
```bash
cd AETHER-CTRG
cp .env.example .env          # one-time
docker compose up -d --build
```
Open **http://localhost:5173**. With `INSTALL_ML=true` (the default in `.env.example`) the
worker image bakes in the real-model stack and **downloads the pretrained weights on first
analysis** (CodeBERT/CLIP/classifier, cached on a Docker volume — so the first Deep run is
slow, then fast). The static engine, IoC extraction, and graph work **offline** immediately;
only weight downloads and the LLM/OSINT enrichers need internet.

> **Low on RAM / want it instant?** Build the lightweight image instead — real static engine
> with mock embeddings/CLIP/FAISS, no large downloads:
> ```bash
> INSTALL_ML=false docker compose up -d --build
> ```

| Service | URL |
|---|---|
| Frontend (SOC console) | http://localhost:5173 |
| API Gateway | http://localhost:4000/api/v1 |
| AI/ML Worker | http://localhost:8000 (`/docs` for Swagger) |
| Neo4j browser | http://localhost:7474 (`neo4j` / value of `NEO4J_PASSWORD`) |

Tear down with `docker compose down` (add `-v` to also drop DB + weight-cache volumes).

#### GPU acceleration (NVIDIA hosts)
On a host with an NVIDIA GPU + `nvidia-container-toolkit`, add the GPU override so the worker
uses CUDA (`ML_DEVICE=auto` then selects the GPU):
```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build
```
The base `docker compose up` stays CPU-only so it runs unchanged on Mac/Windows/Linux.

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

### Tier 2b — Add external OSINT attribution (optional)
Set any subset of provider keys in [.env](.env) to enrich IoCs with reputation and attribute
the sample to a real threat actor (the engine is "available" when ≥1 key is present):
```bash
ABUSEIPDB_API_KEY=...     # IP abuse confidence / geo / ISP
OTX_API_KEY=...           # AlienVault OTX pulses → adversaries + malware families
VT_API_KEY=...            # VirusTotal threat label + analysis stats
```
then `docker compose up -d ml-worker`. New analyses gain an `osint` chip, IP nodes in the
Threat Graph carry real `abuse_confidence`/country/ISP, and `metadata.inferred_actor` comes
from OSINT (falling back to the built-in heuristic when there are no hits). Lookups are
capped + cached to respect free-tier limits (VT 4/min · 500/day, AbuseIPDB 1000/day).

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

### Tier 4 — Swap in YOUR trained model (optional)

The classifier engine ships with a **real, auto-downloading** default
(`ealvaradob/bert-finetuned-phishing`). To plug in your own malware-trained weights — whose
score is **ensembled** with the static engine (definitive signature hits are preserved; the
model raises the score on what signatures miss) — just repoint `CLASSIFIER_PATH`.

**Option A — a HuggingFace Hub id** (auto-downloads, no mounting):
```bash
CLASSIFIER_PATH=your-org/your-malware-clf      # any AutoModelForSequenceClassification repo
CLASSIFIER_NAME=my-malware-clf-v1
CLASSIFIER_MALICIOUS_INDEX=1                    # which output index means "malicious"
```

**Option B — a local model** (`config.json` + `model.safetensors`/`model.onnx` + tokenizer),
mounted under `ml-worker/models/` (git-ignored):
```bash
CLASSIFIER_PATH=/models/malware-clf            # path INSIDE the container
CLASSIFIER_BACKEND=hf                          # hf | onnx (onnx is local-only)
```

Then enable + restart the worker:
```bash
ML_CLASSIFIER_ENABLED=true docker compose up -d ml-worker     # (already built with INSTALL_ML=true)
```

**Verify** — the **AI Engines** page shows *Classifier → Enabled*; new analyses are tagged
`static+ml`, the model score appears as the top SHAP feature, and a **Deep** sandbox run
computes genuine SHAP + LIME token attributions over the model.

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

# worker  (add: pip install -r requirements-ml.txt  for the real models)
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
| POST | `/ai-config` | Toggle `ml_enabled` / `llm_enabled` / `osint_enabled` live |
| GET | `/health` | Gateway + Mongo + Neo4j + worker status |

Worker (`:8000`): `POST /analyze`, `GET/POST /config`, `GET /health`, `GET /docs`.

---

## Environment variables (key ones)

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `INSTALL_ML` | build | `true` | bake the real-model stack (torch/transformers/open_clip/faiss/shap/lime) into the image |
| `ML_DEVICE` | worker | `auto` | `auto`\|`cpu`\|`cuda`\|`mps` — `auto` uses the GPU when present |
| `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` | worker | _(empty)_ / _(empty)_ / `gpt-4o-mini` | external LLM key, OpenAI-compatible endpoint, model id |
| `ML_CLASSIFIER_ENABLED` | worker | `true` | default the classifier engine on (also UI-toggleable) |
| `CLASSIFIER_PATH` | worker | `ealvaradob/bert-finetuned-phishing` | local dir **or HF hub id** (auto-downloads) |
| `CLASSIFIER_NAME` / `CLASSIFIER_BACKEND` | worker | `bert-finetuned-phishing` / `hf` | display name; `hf` or `onnx` (onnx is local-only) |
| `CLASSIFIER_MALICIOUS_INDEX` / `CLASSIFIER_THRESHOLD` | worker | `1` / `0.5` | malicious output index; decision threshold |
| `CLASSIFIER_PREFIX_TYPE` | worker | `false` | prepend a `[file_type]` tag to the model input (keep off for general text models) |
| `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `VT_API_KEY` | worker | _(empty)_ | OSINT provider keys; ≥1 enables the OSINT engine + attribution |
| `TEXT_EMBED_MODEL_ID` / `CLIP_MODEL` / `CLIP_PRETRAINED` | worker | `microsoft/codebert-base` / `ViT-B-32` / `laion2b_s34b_b79k` | embedding + CLIP model ids |
| `XAI_REALSHAP` / `XAI_*` | worker | `true` / caps | real SHAP/LIME (Deep mode) + perf caps (`XAI_MAX_CHARS`, `XAI_SHAP_MAX_EVALS`, …) |
| `OPENCTI_ENABLED` | worker | `false` | turn on the STIX2 push |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | worker | `http://opencti:8080` / _(empty)_ | OpenCTI target + token |
| `MONGO_PASSWORD` / `NEO4J_PASSWORD` | compose | `aether_dev_pw` | DB credentials |
| `OPENCTI_ADMIN_*`, `MINIO_*`, `RABBITMQ_*` | compose | see `.env.example` | OpenCTI stack creds (profile only) |

---

## What's real vs. lightweight

Everything below is **real** when the worker is built with `INSTALL_ML=true` (the default).
Each row degrades to a deterministic mock/static fallback if its dep/key is missing — the
response shape never changes, so the stack always runs.

| Component | Status | File |
|---|---|---|
| Static detection engine (signatures, formats, IoCs, entropy, verdict) | ✅ **Real** (always on) | `ml-worker/app/detect/` |
| Text / image embeddings (CodeBERT 768-d / ResNet-50 2048-d) | ✅ **Real** (ML extras) · mock fallback | `ml-worker/app/models/*_embedding.py` |
| Steganography (CLIP ViT-B/32 + LSB + LLM decode) | ✅ **Real** (ML extras) · structural + mock fallback | `ml-worker/app/models/stego_detector.py` |
| Similarity clustering (FAISS + UMAP + KMeans, labeled corpus) | ✅ **Real** (ML extras) · mock fallback | `ml-worker/app/pipeline/clustering.py` |
| Explainability — SHAP + LIME (Deep mode) | ✅ **Real** over classifier · static signal-attribution fallback | `ml-worker/app/pipeline/xai.py` |
| Trained ML classifier (auto-download, ensembled) | ✅ **Real** (toggleable) | `ml-worker/app/models/classifier.py` |
| External LLM IoC/TTP enrichment + stego decode | ✅ Real (when configured) | `ml-worker/app/models/llm.py` |
| OSINT reputation + threat-actor attribution | ✅ Real (when keyed) · heuristic fallback | `ml-worker/app/intel/osint.py` |
| AI-engine selection / live toggles | ✅ Real | `ml-worker/app/config_state.py`, `routes/config.py` |
| OpenCTI STIX2 push | ✅ Real (when enabled) | `ml-worker/app/integrations/opencti.py` |
| File-type detection, YARA pre-scan | ⚠️ Heuristic | `backend/src/services/` |

**Next upgrades:** real `yara-python` rule sets, malware-trained classifier weights (EMBER/PE
features, CNN-LSTM) in place of the bundled phishing model, and dynamic sandbox detonation —
each slots in behind the existing interfaces.

> ⚠️ Research / education use only. Detonate real malware only in isolated environments.
