"""
AETHER AI/ML Worker — FastAPI entrypoint.

Run (dev):
    uvicorn main:app --reload --port 8000

This microservice owns ALL machine-learning inference. The Node gateway never
imports model code; it only calls this service over HTTP (see backend
src/services/mlClient.js). That boundary is what makes the heavy ML workloads
independently scalable and the mocks trivially swappable.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analyze import router as analyze_router
from app.routes.config import router as config_router

load_dotenv()

app = FastAPI(
    title="AETHER AI/ML Worker",
    version="0.1.0",
    description="Mock malware-analysis inference pipeline (ResNet/BERT/CLIP/LLM mocks).",
)

# CORS — allow the gateway (and, in dev, the frontend) to call directly.
_origins = [o.strip() for o in os.getenv("ML_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(config_router)


@app.get("/")
def root() -> dict:
    """Friendly landing payload so the base URL isn't a bare 404."""
    return {
        "service": "aether-ml-worker",
        "status": "ok",
        "endpoints": {
            "health": "GET /health",
            "analyze": "POST /analyze",
            "docs": "GET /docs",
        },
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "aether-ml-worker"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("ML_WORKER_PORT", "8000")),
        reload=True,
    )
