from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from linksecure.config import settings
from linksecure.core.analyzer import Analyzer
from linksecure.core.result import AnalysisResult

app = FastAPI(
    title="LinkSecure API",
    version="1.0.0",
    description="Servicio de validacion multi-metodo de enlaces",
)

# Permite el consumo desde el frontend Next.js
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_analyzer = Analyzer()


class ValidateRequest(BaseModel):
    url: str = Field(min_length=3, description="URL a analizar")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/validate", response_model=AnalysisResult)
async def validate(payload: ValidateRequest) -> AnalysisResult:
    """Analiza una URL y devuelve veredicto, score y desglose por metodo."""
    return await _analyzer.analyze(payload.url)
