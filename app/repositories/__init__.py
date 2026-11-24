from typing import Optional

from app.config import settings
from app.repositories.base import BaseRepository
from app.repositories.dynamo import DynamoDBRepository
from app.repositories.in_memory import InMemoryRepository
from app.repositories.in_memory import repo as in_memory_repo

_active_repo: Optional[BaseRepository] = None


def set_repository(repo: BaseRepository) -> None:
    """Explicitly sets the active repository instance (e.g. for testing)."""
    global _active_repo
    _active_repo = repo


def get_repository() -> BaseRepository:
    """Dependency provider returning active or configured repository."""
    global _active_repo
    if _active_repo is not None:
        return _active_repo

    if settings.REPOSITORY_BACKEND == "in_memory":
        _active_repo = in_memory_repo
    else:
        _active_repo = DynamoDBRepository()
    return _active_repo


__all__ = [
    "BaseRepository",
    "InMemoryRepository",
    "DynamoDBRepository",
    "get_repository",
    "set_repository",
    "in_memory_repo",
]
