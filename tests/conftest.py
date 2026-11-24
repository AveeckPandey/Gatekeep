from typing import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.repositories import set_repository
from app.repositories.in_memory import repo


@pytest_asyncio.fixture(autouse=True)
async def clean_repository():
    """Ensure repository state is cleanly managed before and after each test."""
    set_repository(repo)
    await repo.reset()
    yield
    await repo.reset()
    set_repository(None)


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Test client for FastAPI app using ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
