# AETHER Framework — MVP

AI-powered automated **malware analysis & threat-actor attribution** platform.
A modular microservices stack built with **mock AI models and mock data** so every
mock can be swapped for a real implementation (PyTorch / HuggingFace / live OSINT)
without touching the surrounding code.

```
┌────────────┐   HTTP    ┌─────────────────┐   HTTP    ┌──────────────────┐
│  Frontend  │ ───────►  │  API Gateway    │ ───────►  │  AI/ML Worker    │
│  React/Vite│           │  Node + Express │           │  Python + FastAPI│
│  :5173     │ ◄───────  │  :4000          │ ◄───────  │  :8000           │
└────────────┘           └────────┬────────┘           └──────────────────┘
                                  │
                     ┌────────────┴────────────┐
                     ▼                          ▼
               MongoDB :27017             Neo4j :7687
            (AnalysisJobs)          (threat-correlation graph)
```

> **No Docker? No problem.** If MongoDB/Neo4j are unreachable the gateway falls
> back to in-memory stores (pre-seeded), so the whole stack runs end-to-end
> without any database installed. Data simply won't persist.

---

## Quick start

### Option A — Full stack in Docker (recommended)
Builds and runs **everything** (frontend + backend + ml-worker + MongoDB + Neo4j):
```bash
docker compose up --build
```
Then open **http://localhost:5173**. First boot waits for the databases to pass
their health checks, seeds mock data, then comes online. Tear down with
`docker compose down` (add `-v` to also drop the database volumes).

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| API Gateway | http://localhost:4000 |
| ML Worker | http://localhost:8000 |
| Neo4j browser | http://localhost:7474 |

---

### Option B — Run services locally (dev)

#### 0. (Optional) Databases only
```bash
cp .env.example .env
docker compose up -d mongo neo4j     # just the datastores
```

#### 1. AI/ML Worker (Python)
```bash
cd ml-worker
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

### 2. API Gateway (Node)
```bash
cd backend
npm install
cp .env.example .env
npm run seed     # seeds Mongo + Neo4j (skips gracefully if not running)
npm run dev      # http://localhost:4000
```

### 3. Frontend (React)
```bash
cd frontend
npm install
cp .env.example .env
npm run dev      # http://localhost:5173
```

Open **http://localhost:5173**, drag a file into **Data Ingestion**, watch the
**Analysis & XAI** view auto-update, then open the **Threat Graph**.

---

## API (gateway, prefix `/api/v1`)

| Method | Path                  | Purpose                                         |
|--------|-----------------------|-------------------------------------------------|
| POST   | `/ingest`             | Upload file → detect type → mock YARA → job_id  |
| GET    | `/analysis/:id`       | Job status + features + IoCs + XAI payload      |
| GET    | `/analysis`           | Recent ingestions (dashboard feed)             |
| GET    | `/threat-graph/:id`   | Correlation subgraph (nodes/edges)             |
| POST   | `/feedback`           | Analyst correction (self-learning loop)        |
| GET    | `/health`             | Gateway + DB + ML-worker status                |

---

## Where the mocks live (swap these for production)

| Mock | File | Replace with |
|------|------|--------------|
| ResNet image embeddings | `ml-worker/app/models/image_embedding.py` | real ResNet forward pass |
| CLIP+LLM stego detector | `ml-worker/app/models/stego_detector.py` | CLIP + LSB extractor + LLM |
| BERT text embeddings | `ml-worker/app/models/text_embedding.py` | HF AutoModel |
| LLM IoC/TTP extractor | `ml-worker/app/models/ioc_extractor.py` | LLM structured-output call |
| t-SNE/UMAP + FAISS | `ml-worker/app/pipeline/clustering.py` | umap-learn + faiss |
| SHAP + LIME | `ml-worker/app/pipeline/xai.py` | shap + lime |
| YARA scan | `backend/src/services/yaraScan.js` | `yara` binary / binding |
| Mock datasets | `backend/data/*.json` | Splunk / MalwareBazaar / OSINT APIs |

All models implement `BaseModelInference` (`ml-worker/app/models/base.py`) and are
wired in the registry at `ml-worker/app/pipeline/__init__.py` — change a single
line there to go live.

---

## Extensibility guarantees (per PRD §5)
1. **Interface segregation** — every model behind `BaseModelInference`.
2. **Env-driven config** — all URIs/keys in `.env` files, never hardcoded.
3. **Component modularity** — React components fetch nothing directly; all I/O is
   in custom hooks (`useAnalysisData`, `useThreatGraph`, `useIngest`).
4. **Feedback loop** — `POST /api/v1/feedback` captures analyst corrections.

> ⚠️ For research/education only. No real malware, network calls, or live OSINT —
> all data is synthetic.
