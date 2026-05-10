from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ECDSA key pair for the ROFL TEE — loaded from env / docker-compose
    SK_ROFL: str  # hex private key (with or without 0x prefix)
    PK_ROFL: str  # hex uncompressed public key (with or without 04/0x prefix)

    # AES-256-GCM symmetric key for encrypting stored embeddings
    SYM_KEY: str  # hex 32-byte key

    # asyncpg DSN, e.g. postgresql://user:pass@host:5432/db
    DATABASE_URL: str

    # Cosine similarity cutoff — embeddings above this are considered the same person
    SIMILARITY_THRESHOLD: float = 0.85


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()