import os
import time
from threading import Lock

from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from hardened_target.agent import HardenedAgentError, chat_with_agent
from hardened_target.audit import clear_events, list_events, new_request_id
from hardened_target.config import settings
from hardened_target.rag_guard import clear_ingested_documents, ingest_document, list_documents


app = FastAPI(
    title="AgentSploit Hardened Target",
    description="Defensive local target for before/after AI security testing.",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_RATE_LIMIT_BUCKETS: dict[str, list[float]] = {}
_RATE_LIMIT_LOCK = Lock()


class ChatRequest(BaseModel):
    message: str | None = Field(None, min_length=1, description="Single user prompt sent to the agent.")
    messages: list[dict[str, str]] | None = Field(
        None,
        description="Optional multi-turn chat messages with role/content keys.",
    )


class ChatResponse(BaseModel):
    request_id: str
    response: str


class IngestRequest(BaseModel):
    title: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    source: str = Field("api")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _configured_api_key() -> str | None:
    return os.getenv("HARDENED_API_KEY") or os.getenv("AGENTSPLOIT_API_KEY") or settings.api_key


def _require_api_key() -> bool:
    return _env_bool("HARDENED_REQUIRE_API_KEY", settings.require_api_key)


def _rate_limit_identity(request: Request, api_key: str | None) -> str:
    if api_key:
        return f"key:{api_key}"
    if request.client and request.client.host:
        return f"ip:{request.client.host}"
    return "ip:unknown"


def _check_api_key(api_key: str | None) -> None:
    if not _require_api_key():
        return

    expected = _configured_api_key()
    if not expected:
        raise HTTPException(status_code=500, detail="HARDENED_API_KEY is required when API key enforcement is enabled.")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-AgentSploit-Key header.")
    if api_key != expected:
        raise HTTPException(status_code=403, detail="Invalid X-AgentSploit-Key header.")


def _check_rate_limit(identity: str) -> None:
    now = time.time()
    window = max(1, settings.rate_limit_window_seconds)
    limit = max(1, settings.rate_limit_requests)

    with _RATE_LIMIT_LOCK:
        bucket = [timestamp for timestamp in _RATE_LIMIT_BUCKETS.get(identity, []) if now - timestamp < window]
        if len(bucket) >= limit:
            _RATE_LIMIT_BUCKETS[identity] = bucket
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        bucket.append(now)
        _RATE_LIMIT_BUCKETS[identity] = bucket


@app.get("/health")
def health() -> dict[str, str]:
    """Simple endpoint to verify that the API process is running."""

    return {"status": "ok", "target": "hardened"}


@app.post("/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    http_request: Request,
    x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key"),
) -> ChatResponse:
    """Forward user input to the hardened AI agent."""

    if not request.message and not request.messages:
        raise HTTPException(status_code=400, detail="Provide either 'message' or 'messages'.")

    _check_api_key(x_agentsploit_key)
    _check_rate_limit(_rate_limit_identity(http_request, x_agentsploit_key))

    request_id = new_request_id()
    user_messages = request.messages if request.messages else request.message or ""

    try:
        answer = chat_with_agent(user_messages=user_messages, request_id=request_id)
    except HardenedAgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return ChatResponse(request_id=request_id, response=answer)


@app.get("/audit-log")
def audit_log(
    request_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key"),
) -> dict[str, object]:
    """Return recent tool-gateway decisions for scanner evidence and debugging."""

    _check_api_key(x_agentsploit_key)
    return {"events": list_events(request_id=request_id, limit=limit)}


@app.post("/audit-log/clear")
def clear_audit_log(x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key")) -> dict[str, int]:
    """Clear audit events before a scan or individual payload."""

    _check_api_key(x_agentsploit_key)
    return {"cleared": clear_events()}


@app.get("/documents")
def documents(x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key")) -> dict[str, object]:
    """List documents currently visible to the hardened RAG tool."""

    _check_api_key(x_agentsploit_key)
    return {"documents": list_documents()}


@app.post("/ingest")
def ingest(
    request: IngestRequest,
    x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key"),
) -> dict[str, object]:
    """Ingest an untrusted document into the local guarded RAG store."""

    _check_api_key(x_agentsploit_key)
    return {"document": ingest_document(request.title, request.content, request.source)}


@app.post("/ingest/clear")
def clear_ingest(x_agentsploit_key: str | None = Header(None, alias="X-AgentSploit-Key")) -> dict[str, int]:
    """Clear documents created through the /ingest endpoint."""

    _check_api_key(x_agentsploit_key)
    return {"cleared": clear_ingested_documents()}
