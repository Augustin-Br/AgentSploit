from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from vulnerable_target.agent import VulnerableAgentError, chat_with_agent


app = FastAPI(
    title="DVAA - Damn Vulnerable AI App",
    description="Intentionally vulnerable LLM agent target for red teaming labs.",
    version="0.1.0",
)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User prompt sent to the agent.")


class ChatResponse(BaseModel):
    response: str


@app.get("/health")
def health() -> dict[str, str]:
    """Simple endpoint to verify that the API process is running."""

    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """Forward user input to the vulnerable AI agent."""

    try:
        answer = chat_with_agent(request.message)
    except VulnerableAgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return ChatResponse(response=answer)
