from __future__ import annotations

from abc import ABC, abstractmethod
from urllib.parse import ParseResult

from linksecure.core.result import MethodResult


class Validator(ABC):
    """Interfaz comun de los validadores de URL."""

    name: str = "Validador"
    weight: float = 1.0

    @abstractmethod
    async def validate(self, url: str, parsed: ParseResult) -> MethodResult:
        """Evalua la URL y devuelve un MethodResult."""

    def _result(self, risk: int, detail: str) -> MethodResult:
        return MethodResult(
            name=self.name, risk=risk, detail=detail, weight=self.weight
        )
