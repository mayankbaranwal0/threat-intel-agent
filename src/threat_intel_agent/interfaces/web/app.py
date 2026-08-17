import asyncio
import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from ...agent import AgentSession
from ...settings import Settings

app = FastAPI(title="threat-intel-agent")
_INDEX = Path(__file__).parent / "static" / "index.html"
_MODES = ("prefer_cache", "prefer_live", "offline")


class _Session:
    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()
        self.tasks: set[asyncio.Task] = set()
        self.agent = AgentSession(
            on_trace=lambda event: self.queue.put_nowait(("trace", event.model_dump()))
        )


_sessions: dict[str, _Session] = {}


def _get(session_id: str) -> _Session:
    if session_id not in _sessions:
        _sessions[session_id] = _Session()
    return _sessions[session_id]


class ChatRequest(BaseModel):
    session_id: str
    message: str


class CommandRequest(BaseModel):
    session_id: str
    command: str
    arg: str | None = None


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_INDEX)


@app.get("/api/config")
async def config() -> dict:
    settings = Settings()
    return {
        "agent_model": settings.agent_model,
        "router_model": settings.router_model,
        "resolver_mode": settings.resolver_mode,
        "sources": {
            "virustotal": bool(settings.vt_api_key),
            "abuseipdb": bool(settings.abuseipdb_api_key),
            "otx": bool(settings.otx_api_key),
            "nvd": True,
            "attck": True,
        },
    }


@app.post("/api/chat", status_code=202)
async def chat(request: ChatRequest) -> dict:
    session = _get(request.session_id)

    async def run() -> None:
        try:
            answer = await session.agent.ask(request.message)
            session.queue.put_nowait(("answer", answer.model_dump()))
        except Exception as e:  # noqa: BLE001 - the background task must surface errors to the SSE stream, not die silently
            session.queue.put_nowait(("error", {"detail": f"{type(e).__name__}: {e}"}))

    task = asyncio.create_task(run())
    session.tasks.add(task)
    task.add_done_callback(session.tasks.discard)
    return {"status": "accepted"}


@app.post("/api/command")
async def command(request: CommandRequest) -> dict:
    session = _get(request.session_id)
    if request.command == "fail" and request.arg:
        session.agent.resolver.arm_failure(request.arg)
        return {"ok": f"armed: next {request.arg} call will simulate an HTTP 429"}
    if request.command == "mode" and request.arg in _MODES:
        session.agent.resolver.mode = request.arg
        return {"ok": f"resolver mode -> {request.arg}"}
    if request.command == "new":
        _sessions.pop(request.session_id, None)
        return {"ok": "session cleared"}
    if request.command == "memory":
        return {"entities": [e.model_dump() for e in session.agent.memory.recent(20)]}
    return {"error": "unknown command"}


@app.get("/api/events/{session_id}")
async def events(session_id: str) -> EventSourceResponse:
    session = _get(session_id)

    async def generate():
        while True:
            kind, payload = await session.queue.get()
            yield {"event": kind, "data": json.dumps(payload)}

    return EventSourceResponse(generate())


def main() -> None:
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
