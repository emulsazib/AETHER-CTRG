# AETHER AI/ML Worker (Python/FastAPI) container image.
# Python 3.12 has prebuilt wheels for all deps (3.14 would force source builds).
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App source.
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
