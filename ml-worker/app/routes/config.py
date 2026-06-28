"""/config — report and toggle the AI detection engines at runtime.

GET  /config  -> which engines are available + currently enabled.
POST /config  -> turn the ML / LLM / OSINT engines on or off live (no restart).
The static engine is always on and cannot be disabled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app import config_state

router = APIRouter()


class ConfigUpdate(BaseModel):
    ml_enabled: Optional[bool] = None
    llm_enabled: Optional[bool] = None
    osint_enabled: Optional[bool] = None


@router.get("/config")
def get_config() -> dict:
    return config_state.get_config()


@router.post("/config")
def set_config(update: ConfigUpdate) -> dict:
    return config_state.update_config(
        ml_enabled=update.ml_enabled,
        llm_enabled=update.llm_enabled,
        osint_enabled=update.osint_enabled,
    )
