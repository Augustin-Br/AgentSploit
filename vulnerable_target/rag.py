import json
import re
from pathlib import Path
from uuid import uuid4

from vulnerable_target.config import PROJECT_ROOT


KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "vulnerable_target" / "knowledge_base"
DATA_DIR = PROJECT_ROOT / "vulnerable_target" / "data"
INGESTED_DOCS_FILE = DATA_DIR / "rag_documents.json"


def _tokenize(text: str) -> set[str]:
    """Tiny keyword tokenizer for a deliberately simple local retriever."""

    return {token.lower() for token in re.findall(r"[a-zA-Z0-9_]{3,}", text)}


def _load_seed_documents() -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    if not KNOWLEDGE_BASE_DIR.exists():
        return documents

    for path in sorted(KNOWLEDGE_BASE_DIR.glob("*.txt")) + sorted(KNOWLEDGE_BASE_DIR.glob("*.md")):
        documents.append(
            {
                "id": f"seed:{path.name}",
                "source": str(path.relative_to(PROJECT_ROOT)),
                "content": path.read_text(encoding="utf-8"),
            }
        )

    return documents


def _load_ingested_documents() -> list[dict[str, str]]:
    if not INGESTED_DOCS_FILE.exists():
        return []

    try:
        data = json.loads(INGESTED_DOCS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    return [item for item in data if isinstance(item, dict)]


def list_documents() -> list[dict[str, str]]:
    """Return all seed and user-ingested documents."""

    return _load_seed_documents() + _load_ingested_documents()


def ingest_document(title: str, content: str, source: str = "api") -> dict[str, str]:
    """Store a document in the vulnerable local knowledge base."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    documents = _load_ingested_documents()
    document = {
        "id": f"ingested:{uuid4().hex[:12]}",
        "title": title,
        "source": source,
        "content": content,
    }
    documents.append(document)
    INGESTED_DOCS_FILE.write_text(json.dumps(documents, indent=2), encoding="utf-8")
    return document


def clear_ingested_documents() -> int:
    """Remove documents created through the /ingest endpoint."""

    documents = _load_ingested_documents()
    if INGESTED_DOCS_FILE.exists():
        INGESTED_DOCS_FILE.unlink()

    return len(documents)


def search_documents(query: str, limit: int = 3) -> str:
    """Return raw document snippets matching a query.

    This is intentionally weak RAG: it returns untrusted document text directly
    to the agent, so prompt injections hidden inside retrieved documents can
    influence later model behavior.
    """

    query_terms = _tokenize(query)
    scored_documents: list[tuple[int, dict[str, str]]] = []

    for document in list_documents():
        haystack = f"{document.get('title', '')} {document.get('source', '')} {document.get('content', '')}"
        score = len(query_terms & _tokenize(haystack))
        if score:
            scored_documents.append((score, document))

    scored_documents.sort(key=lambda item: item[0], reverse=True)
    selected = [document for _, document in scored_documents[:limit]]

    if not selected:
        return "No matching documents found."

    snippets = []
    for document in selected:
        title = document.get("title") or document.get("source", "untitled")
        content = document.get("content", "")
        snippets.append(f"TITLE: {title}\nSOURCE: {document.get('source', 'unknown')}\nCONTENT:\n{content}")

    return "\n\n---\n\n".join(snippets)
