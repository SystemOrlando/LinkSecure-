from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import ParseResult

from linksecure.core.result import MethodResult
from linksecure.validators.base import Validator

try:
    import whois  # python-whois
except ImportError:  # dependencia opcional
    whois = None


class DomainInfoValidator(Validator):
    """Estima reputacion segun la antiguedad del dominio via WHOIS."""

    name = "Reputación WHOIS"
    weight = 0.15

    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        if whois is None:
            return self._result(30, "Modulo WHOIS no disponible")

        host = parsed.hostname or ""
        try:
            data = await asyncio.to_thread(whois.whois, host)
        except Exception as exc:  # noqa: BLE001
            return self._result(35, f"Consulta WHOIS fallida: {exc}")

        created = data.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if not isinstance(created, datetime):
            return self._result(35, "Antiguedad del dominio desconocida")

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < 30:
            return self._result(70, f"Dominio muy reciente ({age_days} dias)")
        if age_days < 180:
            return self._result(40, f"Dominio reciente ({age_days} dias)")
        return self._result(10, f"Dominio establecido ({age_days} dias)")
