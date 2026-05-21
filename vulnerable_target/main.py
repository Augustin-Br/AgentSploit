from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from vulnerable_target.agent import VulnerableAgentError, chat_with_agent
from vulnerable_target.audit import clear_events, list_events, new_request_id
from vulnerable_target.rag import clear_ingested_documents, ingest_document, list_documents


app = FastAPI(
    title="DVAA - Damn Vulnerable AI App",
    description="Intentionally vulnerable LLM agent target for red teaming labs.",
    version="0.1.0",
)


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


@app.get("/health")
def health() -> dict[str, str]:
    """Simple endpoint to verify that the API process is running."""

    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """Forward user input to the vulnerable AI agent."""

    if not request.message and not request.messages:
        raise HTTPException(status_code=400, detail="Provide either 'message' or 'messages'.")

    request_id = new_request_id()
    user_messages = request.messages if request.messages else request.message or ""

    try:
        answer = chat_with_agent(user_messages=user_messages, request_id=request_id)
    except VulnerableAgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return ChatResponse(request_id=request_id, response=answer)


@app.get("/audit-log")
def audit_log(
    request_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, object]:
    """Return recent tool-call audit events for scanner evidence."""

    return {"events": list_events(request_id=request_id, limit=limit)}


@app.post("/audit-log/clear")
def clear_audit_log() -> dict[str, int]:
    """Clear audit events before a scan or individual payload."""

    return {"cleared": clear_events()}


@app.get("/documents")
def documents() -> dict[str, object]:
    """List documents currently visible to the vulnerable RAG tool."""

    return {"documents": list_documents()}


@app.post("/ingest")
def ingest(request: IngestRequest) -> dict[str, object]:
    """Ingest an untrusted document into the vulnerable RAG store."""

    return {"document": ingest_document(request.title, request.content, request.source)}


@app.post("/ingest/clear")
def clear_ingest() -> dict[str, int]:
    """Clear documents created through the /ingest endpoint."""

    return {"cleared": clear_ingested_documents()}
