from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from linksecure.core.result import (
    FAIL_THRESHOLD,
    WARN_THRESHOLD,
    AnalysisResult,
    MethodResult,
    ValidationMethod,
    Verdict,
)
from linksecure.validators.base import Validator
from linksecure.validators.blacklist import BlacklistValidator
from linksecure.validators.domain_info import DomainInfoValidator
from linksecure.validators.heuristics import HeuristicsValidator
from linksecure.validators.reputation_api import ReputationValidator
from linksecure.validators.ssl_check import SSLValidator

# Conjunto de validadores ejecutados por defecto
DEFAULT_VALIDATORS: list[Validator] = [
    BlacklistValidator(),
    HeuristicsValidator(),
    ReputationValidator(),
    SSLValidator(),
    DomainInfoValidator(),
]


class Analyzer:
    """Orquesta los validadores y agrega el resultado final."""

    def __init__(self, validators: list[Validator] | None = None) -> None:
        self.validators = validators or DEFAULT_VALIDATORS

    async def analyze(self, url: str) -> AnalysisResult:
        url = url.strip()
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)

        # Ejecuta todos los validadores en paralelo
        tasks = [v.validate(url, parsed) for v in self.validators]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        methods: list[MethodResult] = []
        for validator, res in zip(self.validators, results):
            if isinstance(res, Exception):
                methods.append(
                    MethodResult(
                        name=validator.name,
                        risk=30,
                        detail=f"Error interno del validador: {res}",
                        weight=validator.weight,
                    )
                )
            else:
                methods.append(res)

        score = self._aggregate(methods)
        return AnalysisResult(
            url=url,
            verdict=self._verdict(score),
            riskScore=score,
            methods=[
                ValidationMethod(name=m.name, status=m.status, detail=m.detail)
                for m in methods
            ],
        )

    @staticmethod
    def _aggregate(methods: list[MethodResult]) -> int:
        # Media ponderada de los riesgos por peso de cada validador
        total_weight = sum(m.weight for m in methods) or 1.0
        score = sum(m.risk * m.weight for m in methods) / total_weight
        return round(min(max(score, 0), 100))

    @staticmethod
    def _verdict(score: int) -> Verdict:
        if score < WARN_THRESHOLD:
            return Verdict.SAFE
        if score < FAIL_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS
