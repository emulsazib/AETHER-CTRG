# Trained ML classifier models

Mount your trained model here so the worker can load it.

```
ml-worker/models/
└── malware-clf/            <-- CLASSIFIER_PATH points here
    ├── config.json
    ├── model.safetensors   (HuggingFace)  OR  model.onnx (ONNX backend)
    ├── tokenizer.json
    └── ...
```

Then set in `.env`:

```
ML_CLASSIFIER_ENABLED=true
CLASSIFIER_PATH=/models/malware-clf
CLASSIFIER_NAME=my-malware-clf-v1
CLASSIFIER_MALICIOUS_INDEX=1
CLASSIFIER_THRESHOLD=0.5
```

and build the worker with the ML deps:

```
docker compose build --build-arg INSTALL_ML=true ml-worker
docker compose up -d ml-worker
```

See the project README → "Plug in your trained model" for the full process.
This directory is git-ignored except for this file.
