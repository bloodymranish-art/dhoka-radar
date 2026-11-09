from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from .rules import analyze
from .llm import explain
from .ratelimit import TokenBucket

app = FastAPI(title="Dhokha Radar")
limiter = TokenBucket(rate_per_min=20, burst=8)
STATIC = Path(__file__).parent.parent / "static"

class Msg(BaseModel):
    text: str

@app.post("/api/analyze")
async def api_analyze(body: Msg, request: Request):
    ip = request.client.host if request.client else "?"
    if not limiter.allow(ip):
        raise HTTPException(429, "Thoda ruko bhai - too many requests.")
    text = body.text.strip()
    if not text or len(text) > 3000:
        raise HTTPException(400, "Message khaali ya bahut lamba hai.")
    report = analyze(text)
    return {**report, "ai": await explain(text, report)}

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
