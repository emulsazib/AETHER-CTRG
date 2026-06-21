# AETHER AI/ML Worker (Python/FastAPI) container image.
# Python 3.12 has prebuilt wheels for all deps (3.14 would force source builds).
FROM python:3.12-slim

WORKDIR /app

# Base dependencies first for layer caching.
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Optional: install the trained-ML-classifier deps (torch/transformers).
# Enable with:  docker compose build --build-arg INSTALL_ML=true ml-worker
ARG INSTALL_ML=false
RUN if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt; fi

# App source.
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
