from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuracion cargada desde variables de entorno o archivo .env."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="LINKSECURE_", extra="ignore"
    )

    # Claves opcionales de servicios de reputacion externos
    google_safebrowsing_key: str | None = None
    virustotal_key: str | None = None

    # Tiempo maximo (segundos) para consultas de red
    request_timeout: int = 8

    # Origenes permitidos para CORS del frontend
    allowed_origins: list[str] = ["http://localhost:3000"]


settings = Settings()
