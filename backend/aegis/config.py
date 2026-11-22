"""Runtime configuration. Every secret comes from the environment; nothing has a default."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Profile(StrEnum):
    LOCAL_DEMO = "local-demo"
    DEFENSIVE_LAB = "defensive-lab"
    DEPLOYMENT_CANDIDATE = "deployment-candidate"


# Bounded limits for ingestion (Section 21.2). Named so they are not magic numbers.
DEFAULT_MAX_BATCH_ITEMS = 500
DEFAULT_MAX_BODY_BYTES = 1_048_576  # 1 MiB
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 900  # 15 minutes
MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=None, extra="ignore")

    profile: Profile = Profile.LOCAL_DEMO
    database_url: SecretStr
    jwt_secret: SecretStr
    jwt_issuer: str = "aegis-local"
    jwt_audience: str = "aegis-api"
    access_token_ttl_seconds: int = Field(default=DEFAULT_ACCESS_TOKEN_TTL_SECONDS, gt=0, le=3600)
    max_batch_items: int = Field(default=DEFAULT_MAX_BATCH_ITEMS, gt=0, le=5000)
    max_body_bytes: int = Field(default=DEFAULT_MAX_BODY_BYTES, gt=0, le=10_485_760)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://127.0.0.1:5173"])
    fixtures_dir: str = "../sample_data/fixtures"
    log_level: str = "INFO"

    @field_validator("jwt_secret")
    @classmethod
    def _secret_strength(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                f"AEGIS_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters"
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
