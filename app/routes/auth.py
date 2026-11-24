from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import (
    TokenResponse,
    User,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository

router = APIRouter(prefix="/api/auth", tags=["Control Plane Auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    repo: BaseRepository = Depends(get_repository),
):
    """
    Register a new tenant user account.
    """
    existing_user = await repo.get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email is already registered",
        )

    hashed_pw = hash_password(payload.password)
    user = User(email=payload.email, hashed_password=hashed_pw)
    created_user = await repo.create_user(user)

    token = create_access_token(data={"sub": created_user.id, "email": created_user.email})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=created_user.id,
            email=created_user.email,
            created_at=created_user.created_at,
        ),
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: UserLoginRequest,
    repo: BaseRepository = Depends(get_repository),
):
    """
    Log in and obtain a JWT access token for the dashboard control plane.
    """
    user = await repo.get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(data={"sub": user.id, "email": user.email})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user.id,
            email=user.email,
            created_at=user.created_at,
        ),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Get profile information of the currently authenticated tenant user.
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        created_at=current_user.created_at,
    )
