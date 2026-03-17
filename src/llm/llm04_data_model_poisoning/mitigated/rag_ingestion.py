"""
LLM04 — Data & Model Poisoning
Safe RAG knowledge-base ingestion with poisoning detection.

Mitigations applied at ingestion time:
  1. Authority-framing pattern scan — rejects documents containing
     instruction-override language (CFO-approved, supersedes, etc.)
  2. Embedding anomaly detection — flags documents whose embedding is
     suspiciously similar to recently ingested ones (coordinated poisoning).

Requires: pip install chromadb openai
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Authority-framing injection patterns
# ---------------------------------------------------------------------------

_AUTHORITY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"supersedes?\s+all\s+previous", re.IGNORECASE),
    re.compile(
        r"(cfo|ceo|cto|devops|admin)\s*[\-—]\s*(approved|authorized|mandated)",
        re.IGNORECASE,
    ),
    re.compile(r"\[\s*(critical|urgent)\s*:", re.IGNORECASE),
    re.compile(r"corrected\s+(figures?|data|report)", re.IGNORECASE),
    re.compile(r"effective\s+immediately", re.IGNORECASE),
    re.compile(r"for\s+(ai\s+)?(systems?|assistants?)\s+only", re.IGNORECASE),
    re.compile(r"if\s+you\s+are\s+(an?\s+)?ai", re.IGNORECASE),
    re.compile(
        r"(new|updated|revised)\s+(policy|instruction|directive)\s*:", re.IGNORECASE
    ),
]

SIMILARITY_THRESHOLD = 0.92  # cosine similarity above this = suspicious
MAX_CLUSTER_SIZE = 2  # more than N similar docs = coordinated poisoning


def _check_authority_framing(content: str) -> Optional[str]:
    """Return the matched pattern string if authority-framing is detected, else None."""
    for pat in _AUTHORITY_PATTERNS:
        m = pat.search(content)
        if m:
            return m.group(0)
    return None


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    import math

    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ---------------------------------------------------------------------------
# Safe ingestion
# ---------------------------------------------------------------------------


def safe_ingest(
    content: str,
    doc_id: str,
    collection,
    embeddings_fn,
) -> dict:
    """Ingest a document only after passing poisoning detection checks.

    Args:
        content       — document text.
        doc_id        — unique document identifier.
        collection    — ChromaDB collection object.
        embeddings_fn — callable(text) → list[float].

    Returns a result dict with keys: accepted, doc_id, reason.
    """
    # Check 1: authority-framing injection pattern
    pattern = _check_authority_framing(content)
    if pattern:
        return {
            "accepted": False,
            "doc_id": doc_id,
            "reason": f"Authority-framing injection pattern detected: '{pattern}'",
        }

    # Compute embedding for the new document
    new_embedding = embeddings_fn(content)

    # Check 2: coordinated poisoning cluster detection
    existing = collection.get(include=["embeddings", "ids"])
    if existing and existing.get("embeddings"):
        similar_docs = []
        for eid, emb in zip(existing["ids"], existing["embeddings"]):
            sim = _cosine_similarity(new_embedding, emb)
            if sim > SIMILARITY_THRESHOLD:
                similar_docs.append({"id": eid, "similarity": round(sim, 4)})

        if len(similar_docs) >= MAX_CLUSTER_SIZE:
            return {
                "accepted": False,
                "doc_id": doc_id,
                "reason": (
                    f"Coordinated poisoning cluster detected: "
                    f"{len(similar_docs)} very similar documents already in store "
                    f"(threshold={SIMILARITY_THRESHOLD}). "
                    f"Similar IDs: {[d['id'] for d in similar_docs]}"
                ),
            }

    # All checks passed — ingest
    collection.add(
        documents=[content],
        embeddings=[new_embedding],
        ids=[doc_id],
    )
    return {"accepted": True, "doc_id": doc_id, "reason": "All checks passed."}
