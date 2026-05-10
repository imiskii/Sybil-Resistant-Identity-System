from __future__ import annotations

import asyncpg

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS embeddings (
    db_key      TEXT PRIMARY KEY,
    payload     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def create_pool(dsn: str) -> asyncpg.Pool:
    """Create and return an asyncpg connection pool."""
    return await asyncpg.create_pool(dsn)


async def close_pool(pool: asyncpg.Pool) -> None:
    """Gracefully close the connection pool."""
    await pool.close()


async def init_db(pool: asyncpg.Pool) -> None:
    """Create the embeddings table if it does not already exist."""
    async with pool.acquire() as conn:
        await conn.execute(CREATE_TABLE_SQL)


async def fetch_all_embeddings(pool: asyncpg.Pool) -> list[tuple[str, bytes]]:
    """Return all (db_key, payload) rows from the embeddings table."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT db_key, payload FROM embeddings;")
    return [(row["db_key"], bytes(row["payload"])) for row in rows]


async def insert_embedding(pool: asyncpg.Pool, db_key: str, payload: bytes) -> None:
    """Insert a new embedding row, silently ignoring duplicate db_key conflicts."""
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO embeddings (db_key, payload) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
            db_key,
            payload,
        )


async def key_exists(pool: asyncpg.Pool, db_key: str) -> bool:
    """Return True if db_key is already present in the embeddings table."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT 1 FROM embeddings WHERE db_key = $1;", db_key)
    return row is not None
