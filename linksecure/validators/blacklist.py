from __future__ import annotations

from urllib.parse import ParseResult

from linksecure.core.result import MethodResult
from linksecure.validators.base import Validator

# Semilla local de dominios reconocidos como maliciosos
_LOCAL_BLACKLIST = {
    "malware.testing.google.test",
    "phishing.example",
    "testsafebrowsing.appspot.com",
}

# TLDs con tasa de abuso historicamente alta
_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml"}


class BlacklistValidator(Validator):
    """Contrasta el dominio contra listas negras locales y TLDs de riesgo."""

    name = "Blacklist"
    weight = 0.35

    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        host = (parsed.hostname or "").lower()

        if host in _LOCAL_BLACKLIST:
            return self._result(100, "Dominio presente en lista negra local")

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in _SUSPICIOUS_TLDS:
            return self._result(55, f"TLD '.{tld}' asociado a abuso frecuente")

        return self._result(5, "Sin coincidencias en listas negras")
