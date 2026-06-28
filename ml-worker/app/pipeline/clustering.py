"""
Similarity clustering used to group related malware samples and reduce false
positives.

REAL: ``FaissClustering`` — embeds the built-in labeled reference corpus
(reference_corpus.py) with the SAME encoder as the query, then:
  * FAISS ``IndexFlatIP`` over L2-normalized vectors → cosine nearest neighbors,
  * KMeans (fit once on the corpus) → ``cluster_id``,
  * UMAP (fit once, ``transform`` the query) → 2-D ``coords_2d`` (PCA fallback).

FALLBACK: ``MockClustering`` — deterministic pseudo-coordinates/scores, used when
the ML extras are absent, for image queries (no image reference corpus shipped),
or on any failure. ``get_clustering()`` picks one. Both return the same shape.

Per-MODALITY separation (text vs image) means the 768-d CodeBERT space and the
2048-d ResNet space never share an index, so their dims can't clash.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from typing import Any, Dict, List, Optional

from . import reference_corpus

logger = logging.getLogger("aether.clustering")

_KMEANS_K = int(os.getenv("CLUSTER_KMEANS_K", "5"))
_UMAP_NEIGHBORS = int(os.getenv("CLUSTER_UMAP_NEIGHBORS", "15"))
_INDEX_DIR = os.getenv("CLUSTER_INDEX_DIR", "")


# Mock corpus the deterministic fallback "searches" against.
_KNOWN_SAMPLES = [
    {"sample": "Lumma Stealer", "sha256_prefix": "a1b2c3d4"},
    {"sample": "SocGholish (APT29)", "sha256_prefix": "f00dcafe"},
    {"sample": "AsyncRAT (APT29)", "sha256_prefix": "01234567"},
]


class MockClustering:
    name = "clustering_faiss"
    backing_architecture = "UMAP/t-SNE + FAISS (mock)"

    def compute(self, payload: Dict[str, Any], embedding: List[float]) -> Dict[str, Any]:
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


class FaissClustering:
    name = "clustering_faiss"
    backing_architecture = "FAISS IndexFlatIP + UMAP + KMeans"

    def __init__(self) -> None:
        self._fallback = MockClustering()
        self._text_bank: Optional[Dict[str, Any]] = None
        self._text_bank_built = False

    # ---- corpus embedding + bank construction --------------------------------
    def _embed_one(self, embedder, text: str) -> List[float]:
        payload = {
            "file_name": "corpus",
            "content_b64": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "file_type": "JS",
        }
        return embedder.infer(payload)["embedding"]

    def _embed_corpus(self, embedder, texts: List[str]):
        import numpy as np

        # Probe once to learn the embedder's TRUE output dim. Including it in the
        # cache key keeps a mock-fallback run (16-d) from ever poisoning a real run
        # (768-d) — the two write/read different cache files.
        dim = len(self._embed_one(embedder, "probe"))
        model_id = os.getenv("TEXT_EMBED_MODEL_ID", "microsoft/codebert-base")
        fp = hashlib.sha256((f"{model_id}|d{dim}|" + "||".join(texts)).encode()).hexdigest()[:16]
        cache = os.path.join(_INDEX_DIR, f"text_{fp}.npz") if _INDEX_DIR else ""

        if cache and os.path.exists(cache):
            try:
                arr = np.load(cache)["emb"].astype("float32")
                if arr.shape == (len(texts), dim):
                    return arr
            except Exception as exc:  # noqa: BLE001
                logger.info("FAISS corpus cache unreadable (%s); rebuilding.", exc)

        arr = np.asarray([self._embed_one(embedder, t) for t in texts], dtype="float32")

        if cache and arr.ndim == 2 and arr.shape[1] == dim:
            try:
                os.makedirs(_INDEX_DIR, exist_ok=True)
                np.savez(cache, emb=arr)
            except Exception as exc:  # noqa: BLE001
                logger.info("Could not persist FAISS corpus (%s); continuing.", exc)
        return arr

    def _build_text_bank(self) -> Optional[Dict[str, Any]]:
        from app.models.text_embedding import get_text_embedder

        embedder = get_text_embedder()
        entries = reference_corpus.TEXT_CORPUS
        texts = [e["text"] for e in entries]

        import faiss
        import numpy as np

        emb = self._embed_corpus(embedder, texts)  # [N, dim] float32
        if emb.ndim != 2 or emb.shape[0] < 2:
            return None
        n, dim = emb.shape

        norm = emb.copy()
        faiss.normalize_L2(norm)
        index = faiss.IndexFlatIP(dim)
        index.add(norm)

        # KMeans cluster_id (clamp k <= n or it raises).
        kmeans = None
        try:
            from sklearn.cluster import KMeans

            k = max(2, min(_KMEANS_K, n))
            kmeans = KMeans(n_clusters=k, n_init=10, random_state=42).fit(norm)
        except Exception as exc:  # noqa: BLE001
            logger.info("KMeans unavailable (%s); cluster_id will be hashed.", exc)

        # UMAP 2-D projection (fit once); PCA fallback for the tiny-corpus quirk.
        reducer = None
        try:
            import umap

            reducer = umap.UMAP(
                n_neighbors=max(2, min(_UMAP_NEIGHBORS, n - 1)),
                n_components=2,
                metric="cosine",
                random_state=42,
            ).fit(norm)
        except Exception as exc:  # noqa: BLE001
            logger.info("UMAP fit failed (%s); will use PCA for coords.", exc)
            try:
                from sklearn.decomposition import PCA

                reducer = ("pca", PCA(n_components=2, random_state=42).fit(norm))
            except Exception:  # noqa: BLE001
                reducer = None

        return {
            "index": index,
            "labels": [e["sample"] for e in entries],
            "families": [e["family"] for e in entries],
            "kmeans": kmeans,
            "reducer": reducer,
            "dim": dim,
            "n": n,
        }

    def _get_text_bank(self) -> Optional[Dict[str, Any]]:
        if not self._text_bank_built:
            try:
                self._text_bank = self._build_text_bank()
            except Exception as exc:  # noqa: BLE001
                logger.warning("FAISS text bank build failed (%s); using mock.", exc)
                self._text_bank = None
            self._text_bank_built = True
        return self._text_bank

    # ---- query ----------------------------------------------------------------
    def _coords(self, bank, qn) -> Dict[str, float]:
        reducer = bank.get("reducer")
        try:
            if reducer is None:
                raise RuntimeError("no reducer")
            if isinstance(reducer, tuple) and reducer[0] == "pca":
                pt = reducer[1].transform(qn)[0]
            else:
                pt = reducer.transform(qn)[0]
            return {"x": round(float(pt[0]), 4), "y": round(float(pt[1]), 4)}
        except Exception as exc:  # noqa: BLE001
            logger.info("coords projection failed (%s); hashing coords.", exc)
            seed = int(hashlib.sha256(str(qn[0][:4]).encode()).hexdigest()[:8], 16)
            return {
                "x": round(((seed % 1000) / 1000.0) * 2 - 1, 4),
                "y": round((((seed >> 8) % 1000) / 1000.0) * 2 - 1, 4),
            }

    def compute(self, payload: Dict[str, Any], embedding: List[float]) -> Dict[str, Any]:
        # No image reference corpus is shipped → image queries use the mock.
        if not embedding or payload.get("file_type") == "Image":
            return self._fallback.compute(payload, embedding)

        bank = self._get_text_bank()
        if not bank or len(embedding) != bank["dim"]:
            return self._fallback.compute(payload, embedding)

        try:
            import faiss
            import numpy as np

            q = np.asarray([embedding], dtype="float32")
            faiss.normalize_L2(q)

            k = min(3, bank["n"])
            scores, idxs = bank["index"].search(q, k)
            neighbors = []
            for rank in range(k):
                i = int(idxs[0][rank])
                if i < 0:
                    continue
                neighbors.append({
                    "sample": bank["labels"][i],
                    "score": round(max(float(scores[0][rank]), 0.05), 3),
                })
            neighbors.sort(key=lambda nb: nb["score"], reverse=True)

            if bank["kmeans"] is not None:
                cluster_id = int(bank["kmeans"].predict(q)[0])
            else:
                cluster_id = int(hashlib.sha256(str(embedding[:4]).encode()).hexdigest()[:8], 16) % 5

            return {
                "model": self.name,
                "backing_architecture": self.backing_architecture,
                "coords_2d": self._coords(bank, q),
                "cluster_id": cluster_id,
                "neighbors": neighbors,
                # Overwritten by the pipeline (anchored to the ensembled risk).
                "false_positive_estimate": 0.03,
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("FAISS query failed (%s); using mock clustering.", exc)
            return self._fallback.compute(payload, embedding)


def get_clustering():
    """Real FAISS clustering when the ML extras are installed, else the mock."""
    from app.models import _runtime

    if _runtime.ml_available("faiss", "sklearn", "umap"):
        return FaissClustering()
    return MockClustering()
