from __future__ import annotations

import base64
from urllib.parse import ParseResult

import httpx

from linksecure.config import settings
from linksecure.core.result import MethodResult
from linksecure.validators.base import Validator


class ReputationValidator(Validator):
    """Consulta servicios externos de reputacion (Safe Browsing, VirusTotal)."""

    name = "Reputación (APIs externas)"
    weight = 0.25

    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        checks: list[tuple[int, str]] = []

        if settings.google_safebrowsing_key:
            checks.append(await self._safe_browsing(url))
        if settings.virustotal_key:
            checks.append(await self._virustotal(url))

        if not checks:
            return self._result(30, "Sin claves de API configuradas; omitido")

        # El riesgo agregado es el peor reportado por los servicios
        risk = max(risk for risk, _ in checks)
        detail = "; ".join(detail for _, detail in checks)
        return self._result(risk, detail)

    async def _safe_browsing(self, url: str) -> tuple[int, str]:
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "linksecure", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                resp = await client.post(
                    endpoint,
                    params={"key": settings.google_safebrowsing_key},
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            return 30, f"Safe Browsing sin respuesta ({exc})"

        if data.get("matches"):
            return 100, "Google Safe Browsing marco la URL como amenaza"
        return 5, "Google Safe Browsing: limpia"

    async def _virustotal(self, url: str) -> tuple[int, str]:
        # VirusTotal v3 identifica la URL por su base64 url-safe sin padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": settings.virustotal_key}
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 404:
                    return 20, "VirusTotal: URL sin analisis previo"
                resp.raise_for_status()
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        except Exception as exc:  # noqa: BLE001
            return 30, f"VirusTotal sin respuesta ({exc})"

        flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
        if flagged >= 3:
            return 100, f"VirusTotal: {flagged} motores marcan la URL"
        if flagged >= 1:
            return 60, f"VirusTotal: {flagged} motor(es) con alertas"
        return 5, "VirusTotal: limpia"
