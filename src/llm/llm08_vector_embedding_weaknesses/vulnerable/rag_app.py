"""
LLM08 — Vector & Embedding Weaknesses
Vulnerable RAG application.

Uses a shared ChromaDB collection with no ingestion validation.
Any document can be added; poisoned documents rank above legitimate ones.
Cross-tenant isolation is absent — all users share one namespace.

Run:
    python -m src.llm.llm08_vector_embedding_weaknesses.vulnerable.rag_app
"""

from __future__ import annotations

import os, sys, math, textwrap
from dotenv import load_dotenv

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

from openai import OpenAI

client = OpenAI()

# ---------------------------------------------------------------------------
# In-process vector store (no ChromaDB dependency needed for the PoC)
# ---------------------------------------------------------------------------


class _SimpleVectorStore:
    """Minimal in-memory vector store with cosine similarity retrieval."""

    def __init__(self):
        self._docs: list[str] = []
        self._embeddings: list[list[float]] = []
        self._ids: list[str] = []
        self._tenants: list[str] = []

    def add(self, doc: str, doc_id: str, tenant: str = "shared") -> None:
        emb = _embed(doc)
        self._docs.append(doc)
        self._embeddings.append(emb)
        self._ids.append(doc_id)
        self._tenants.append(tenant)

    def query(self, text: str, n: int = 3, tenant: str | None = None) -> list[str]:
        q_emb = _embed(text)
        scores = [
            (_cosine(q_emb, e), i)
            for i, e in enumerate(self._embeddings)
            if tenant is None or self._tenants[i] == tenant
        ]
        scores.sort(reverse=True)
        return [self._docs[i] for _, i in scores[:n]]


_STORE = _SimpleVectorStore()
_EMBED_CACHE: dict[str, list[float]] = {}


def _embed(text: str) -> list[float]:
    if text not in _EMBED_CACHE:
        resp = client.embeddings.create(model="text-embedding-3-small", input=text)
        _EMBED_CACHE[text] = resp.data[0].embedding
    return _EMBED_CACHE[text]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(x * x for x in b))
    return dot / mag if mag else 0.0


def _ask_llm(question: str, context: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "Answer the question using only the provided context.",
            },
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
        ],
        max_tokens=256,
    )
    return resp.choices[0].message.content or ""


def ingest(doc: str, doc_id: str) -> None:
    """Ingest a document. VULNERABLE: no validation."""
    _STORE.add(doc, doc_id)
    print(f"  [ingested] {doc_id}")


def query(question: str) -> str:
    """Answer using RAG. VULNERABLE: no retrieval integrity check."""
    chunks = _STORE.query(question, n=3)
    context = "\n---\n".join(chunks) if chunks else "No documents found."
    return _ask_llm(question, context)


# ---------------------------------------------------------------------------
# Seed with legitimate data
# ---------------------------------------------------------------------------


def _seed() -> None:
    ingest(
        "Q4 2025 revenue: $24.7M. Operating expenses: $18.2M. Net income: $6.5M.",
        "finance_q4_official",
    )
    ingest(
        "The production API endpoint is api.acmecorp.com/v2. Auth via OAuth2.",
        "infra_api_official",
    )
    ingest(
        "Refund policy: requests under $500 are approved automatically within 24h.",
        "policy_refunds",
    )


_seed()

# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM08 — Vector & Embedding Weaknesses  │  VULNERABLE   │
    │  Commands: /ingest <text>  /query <q>  /quit            │
    └─────────────────────────────────────────────────────────┘
""")


def main() -> None:
    print(BANNER)
    _doc_counter = [0]
    while True:
        try:
            inp = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not inp:
            continue
        if inp.lower() in ("/quit", "/exit"):
            break
        if inp.lower().startswith("/ingest "):
            text = inp[8:].strip()
            _doc_counter[0] += 1
            ingest(text, f"user_doc_{_doc_counter[0]}")
            print(f"  Ingested.\n")
        elif inp.lower().startswith("/query ") or not inp.startswith("/"):
            q = inp[7:] if inp.lower().startswith("/query ") else inp
            print(f"\nAgent: {query(q)}\n")
        else:
            print("  Commands: /ingest <text>  /query <q>  /quit\n")


if __name__ == "__main__":
    main()
