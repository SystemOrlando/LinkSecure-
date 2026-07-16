from __future__ import annotations

import re
from urllib.parse import ParseResult

from linksecure.core.result import MethodResult
from linksecure.validators.base import Validator

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Palabras habituales en campanas de phishing
_PHISHING_WORDS = (
    "login", "verify", "account", "secure", "update", "banco",
    "confirm", "wallet", "free", "bonus", "gift", "password",
)


class HeuristicsValidator(Validator):
    """Detecta patrones de ofuscacion tipicos en URLs maliciosas."""

    name = "Heurísticas"
    weight = 0.20

    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        host = (parsed.hostname or "").lower()
        risk = 0
        flags: list[str] = []

        if _IP_RE.match(host):
            risk += 40
            flags.append("host es una IP literal")
        if "@" in url:
            risk += 35
            flags.append("URL contiene '@' (ofuscacion de destino)")
        if host.startswith("xn--") or ".xn--" in host:
            risk += 30
            flags.append("dominio punycode (posible homografo)")
        if host.count(".") >= 4:
            risk += 15
            flags.append("exceso de subdominios")
        if len(url) > 90:
            risk += 10
            flags.append("URL inusualmente larga")
        if host.count("-") >= 3:
            risk += 10
            flags.append("multiples guiones en el dominio")
        if any(w in url.lower() for w in _PHISHING_WORDS):
            risk += 15
            flags.append("palabras tipicas de phishing")

        risk = min(risk, 100)
        detail = "; ".join(flags) if flags else "Sin patrones de ofuscacion detectados"
        return self._result(risk, detail)
