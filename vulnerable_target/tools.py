from pathlib import Path

from vulnerable_target.config import PROJECT_ROOT
from vulnerable_target.rag import search_documents as rag_search_documents


def read_system_file(filepath: str) -> str:
    """Read a local file and return its content.

    This function is intentionally vulnerable: it does not validate allowed
    paths, file extensions, or sensitive filenames. A real agent should never
    expose a filesystem tool this way.
    """

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
    """Mock email sender.

    The function only prints the message so the lab remains safe to run locally.
    It is still exposed to the agent as if it were a real external action.
    """

    print("=== MOCK EMAIL SENT ===")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print(body)
    print("=======================")
    return f"Mock email sent to {to}"


def search_documents(query: str, limit: int = 3) -> str:
    """Search the local RAG knowledge base.

    This tool is intentionally unsafe because it returns raw untrusted document
    content directly to the agent.
    """

    return rag_search_documents(query=query, limit=limit)
