"""
/analyze route — the single entrypoint the Node API Gateway calls over HTTP.

Request : AnalyzeRequest (file_type, file_name, content_b64?, sandbox_mode)
Response : the combined pipeline payload (features, IoCs, clustering, XAI).
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.pipeline import run_pipeline

router = APIRouter()

FileType = Literal["PDF", "Image", "JS", "Archive", "Unknown"]
SandboxMode = Literal["Immediate", "Deep"]


class AnalyzeRequest(BaseModel):
    file_type: FileType = "Unknown"
    file_name: str = Field(default="sample.bin")
    # Base64 of the uploaded file. Optional for the mock pipeline (which keys off
    # name/type) but kept so real models have the bytes when swapped in.
    content_b64: Optional[str] = None
    sandbox_mode: SandboxMode = "Immediate"


@router.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    # Deep sandboxing would, in a real system, also detonate the sample and merge
    # dynamic behavior. The mock pipeline annotates the mode for the UI.
    result = run_pipeline(req.model_dump())
    result["sandbox_mode"] = req.sandbox_mode
    result["file_name"] = req.file_name
    return result
