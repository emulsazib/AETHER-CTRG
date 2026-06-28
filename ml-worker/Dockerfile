# AETHER AI/ML Worker (Python/FastAPI) container image.
# Python 3.12 has prebuilt wheels for all deps (3.14 would force source builds).
#
# GPU NOTE: the cu121 torch/torchvision wheels in requirements-ml.txt bundle the
# CUDA runtime + cuDNN, so a plain python:3.12-slim base + `--gpus`/compose
# `deploy.reservations.devices` + the host nvidia-container-toolkit is enough for
# inference (no full CUDA toolkit / source build needed). If a target driver
# rejects the bundled libs, switch the base to:
#     FROM nvidia/cuda:12.1.0-cudnn8-runtime-ubuntu22.04
# and install Python 3.12 + the same wheels.
FROM python:3.12-slim

WORKDIR /app

# System libs: libgomp1 = OpenMP runtime for faiss/sklearn/torch; git = some HF /
# open_clip metadata paths expect it. curl kept for debugging/healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 git \
    && rm -rf /var/lib/apt/lists/*

# Cache real-model weights on mounted volumes so they download once (see compose).
ENV HF_HOME=/root/.cache/huggingface \
    TORCH_HOME=/root/.cache/torch

# Base dependencies first for layer caching.
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the REAL-MODEL stack (torch/transformers/open_clip/faiss/shap/lime/...).
# Defaults ON now that the pipeline ships real models; build with
#   docker compose build --build-arg INSTALL_ML=false ml-worker
# to get the lightweight mock-only image instead.
ARG INSTALL_ML=true
RUN if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt; fi

# App source.
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
