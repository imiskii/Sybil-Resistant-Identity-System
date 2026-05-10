from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.config import get_settings
from app.database import close_pool, create_pool, init_db
from app.embedding import load_model
from app.routes.connection import router as connection_router
from app.routes.register import router as register_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    app.state.settings = settings
    app.state.pool = await create_pool(settings.DATABASE_URL)
    await init_db(app.state.pool)
    app.state.model = load_model()
    yield
    await close_pool(app.state.pool)


app = FastAPI(title="ROFL Mock", lifespan=lifespan)
app.include_router(register_router)
app.include_router(connection_router)
