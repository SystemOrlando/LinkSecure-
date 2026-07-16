from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field


class MethodStatus(str, Enum):
    """Estado individual de un validador."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class Verdict(str, Enum):
    """Veredicto agregado del analisis."""

    SAFE = "Seguro"
    SUSPICIOUS = "Sospechoso"
    MALICIOUS = "Malicioso"


# Umbrales compartidos (riesgo 0-100)
WARN_THRESHOLD = 30
FAIL_THRESHOLD = 70


@dataclass
class MethodResult:
    """Resultado interno de un validador antes de exponerse al frontend."""

    name: str
    risk: int          # riesgo detectado 0-100
    detail: str
    weight: float = 1.0  # peso en el score agregado

    @property
    def status(self) -> MethodStatus:
        if self.risk < WARN_THRESHOLD:
            return MethodStatus.PASS
        if self.risk < FAIL_THRESHOLD:
            return MethodStatus.WARN
        return MethodStatus.FAIL


# Modelos de respuesta: contrato exacto con el frontend
class ValidationMethod(BaseModel):
    name: str
    status: MethodStatus
    detail: str


class AnalysisResult(BaseModel):
    url: str
    verdict: Verdict
    riskScore: int = Field(ge=0, le=100)
    methods: list[ValidationMethod]
