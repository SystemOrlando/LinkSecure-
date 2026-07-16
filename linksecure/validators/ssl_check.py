from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import ParseResult

from linksecure.config import settings
from linksecure.core.result import MethodResult
from linksecure.validators.base import Validator


class SSLValidator(Validator):
    """Verifica presencia, validez y vigencia del certificado TLS."""

    name = "Certificado SSL/TLS"
    weight = 0.15

    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        if parsed.scheme != "https":
            return self._result(70, "La conexion no usa HTTPS")

        host = parsed.hostname or ""
        port = parsed.port or 443
        try:
            cert = await asyncio.to_thread(self._fetch_cert, host, port)
        except Exception as exc:  # noqa: BLE001
            return self._result(60, f"No se pudo validar el certificado: {exc}")

        not_after = cert.get("notAfter")
        if not_after:
            expires = datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days = (expires - datetime.now(timezone.utc)).days
            if days < 0:
                return self._result(90, "Certificado expirado")
            if days < 15:
                return self._result(45, f"Certificado expira pronto ({days} dias)")

        return self._result(5, "Certificado valido y vigente")

    @staticmethod
    def _fetch_cert(host: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=settings.request_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert() or {}
