"""
MockClustering — stands in for t-SNE/UMAP dimensionality reduction + FAISS
nearest-neighbor similarity search used to group related malware samples and
reduce false positives.

REAL REPLACEMENT:
    - Reduce embeddings with umap-learn or sklearn.manifold.TSNE -> 2D coords.
    - Build / query a faiss.IndexFlatIP over the corpus of known embeddings.
Keep the return shape: { coords_2d, neighbors:[{sample,score}], cluster_id }.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

# A tiny mock corpus of "known" samples FAISS would search against.
_KNOWN_SAMPLES = [
    {"sample": "Lumma Stealer", "sha256_prefix": "a1b2c3d4"},
    {"sample": "SocGholish (APT29)", "sha256_prefix": "f00dcafe"},
    {"sample": "AsyncRAT (APT29)", "sha256_prefix": "01234567"},
]


class MockClustering:
    name = "clustering_faiss"
    backing_architecture = "UMAP/t-SNE + FAISS (mock)"

    def compute(self, payload: Dict[str, Any], embedding: List[float]) -> Dict[str, Any]:
        # MOCK: derive stable pseudo-coordinates and similarity scores from the
        # embedding/input. Replace with real UMAP projection + FAISS search.
        basis = f"{payload.get('file_name','')}|{len(embedding)}"
        seed = int(hashlib.sha256(basis.encode()).hexdigest()[:8], 16)

        x = round(((seed % 1000) / 1000.0) * 2 - 1, 4)
        y = round((((seed >> 8) % 1000) / 1000.0) * 2 - 1, 4)

        neighbors = []
        for i, known in enumerate(_KNOWN_SAMPLES):
            score = round(0.95 - i * 0.18 - ((seed >> (i + 1)) % 7) / 100.0, 3)
            neighbors.append({"sample": known["sample"], "score": max(score, 0.05)})
        neighbors.sort(key=lambda n: n["score"], reverse=True)

        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "coords_2d": {"x": x, "y": y},
            "cluster_id": seed % 5,
            "neighbors": neighbors,
            "false_positive_estimate": round(0.02 + (seed % 3) / 100.0, 3),
        }
