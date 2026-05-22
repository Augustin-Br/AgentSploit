from pathlib import Path

from hardened_target.config import PROJECT_ROOT
from hardened_target.rag_guard import search_documents as guarded_search_documents


def read_system_file(filepath: str) -> str:
    """Read a local file after the tool gateway has authorized the path."""

    requested_path = Path(filepath)
    if not requested_path.is_absolute():
        requested_path = PROJECT_ROOT / requested_path

    try:
        return requested_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"File not found: {filepath}"
    except PermissionError:
        return f"Permission denied: {filepath}"
    except OSError as exc:
        return f"Could not read {filepath}: {exc}"


def send_email(to: str, subject: str, body: str) -> str:
    """Local-only mock sender used after policy authorization."""

    print("=== HARDENED MOCK MESSAGE SENT ===")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print(body)
    print("==================================")
    return f"Mock message queued for {to}"


def search_documents(query: str, limit: int = 3) -> str:
    """Search the guarded local RAG knowledge base."""

    return guarded_search_documents(query=query, limit=limit)
