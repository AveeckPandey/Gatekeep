import asyncio
import secrets
import threading
import time
from collections import defaultdict
from typing import Dict, List

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from app.config import settings
from app.core import cognito
from app.core.dependencies import get_current_user
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.api_key import ApiKey
from app.models.policy import Policy, PolicyMode
from app.models.user import (
    TokenResponse,
    User,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.models.workspace import Workspace
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository

router = APIRouter(prefix="/api/auth", tags=["Control Plane Auth"])


class ConfirmRequest(BaseModel):
    email: EmailStr
    code: str


class ResendConfirmationRequest(BaseModel):
    email: EmailStr


@router.post("/resend-confirmation")
async def resend_confirmation(payload: ResendConfirmationRequest):
    if settings.AUTH_BACKEND != "cognito":
        raise HTTPException(status_code=404, detail="Cognito authentication is not configured")
    try:
        result = await cognito.resend_confirmation_code(str(payload.email))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in {"LimitExceededException", "TooManyRequestsException"}:
            raise HTTPException(status_code=429, detail="Please wait before requesting another code.") from exc
        if code == "CodeDeliveryFailureException":
            raise HTTPException(status_code=502, detail="Cognito could not deliver the email. Please try again later.") from exc
        raise HTTPException(status_code=400, detail="Could not resend a confirmation code for this account.") from exc
    return {
        "message": "A new confirmation code was sent.",
        "destination": result.get("CodeDeliveryDetails", {}).get("Destination"),
    }


@router.post("/confirm")
async def confirm_registration(payload: ConfirmRequest):
    if settings.AUTH_BACKEND != "cognito":
        raise HTTPException(status_code=404, detail="Cognito authentication is not configured")
    try:
        await cognito.confirm_sign_up(str(payload.email), payload.code)
    except ClientError as exc:
        raise HTTPException(status_code=400, detail=exc.response["Error"]["Code"]) from exc
    return {"message": "Account confirmed. Sign in to continue."}

# In-memory tracking for login brute-force rate limiting
_login_failures: Dict[str, List[float]] = defaultdict(list)
_login_lock = threading.Lock()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    repo: BaseRepository = Depends(get_repository),
):
    """
    Register a new tenant user account.
    """
    if settings.AUTH_BACKEND == "cognito":
        try:
            result = await cognito.sign_up(str(payload.email), payload.password)
        except ClientError as exc:
            raise HTTPException(status_code=400, detail=exc.response["Error"]["Code"]) from exc
        return {"confirmation_required": not result.get("UserConfirmed", False)}
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
    Enforces brute-force protection (max 10 failed attempts per minute per email).
    """
    if settings.AUTH_BACKEND == "cognito":
        try:
            result = await cognito.authenticate(str(payload.email), payload.password)
            auth = result.get("AuthenticationResult")
            if not auth:
                raise HTTPException(status_code=401, detail="Additional Cognito challenge required")
            token = auth["AccessToken"]
            claims = await asyncio.to_thread(cognito.verify_cognito_access_token, token)
            user = await repo.get_user_by_id(claims["sub"])
            if not user:
                user = await repo.create_user(User(id=claims["sub"], email=payload.email, hashed_password=""))
            return TokenResponse(access_token=token, user=UserResponse(id=user.id, email=user.email, created_at=user.created_at))
        except ClientError as exc:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
    now = time.time()
    email_key = payload.email.lower()

    with _login_lock:
        recent = [t for t in _login_failures[email_key] if t > now - 60]
        _login_failures[email_key] = recent
        if len(recent) >= 10:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please wait 1 minute before trying again.",
                headers={"Retry-After": "60"},
            )

    user = await repo.get_user_by_email(email_key)
    if not user or not verify_password(payload.password, user.hashed_password):
        with _login_lock:
            _login_failures[email_key].append(now)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reset failure counter on successful authentication
    with _login_lock:
        _login_failures.pop(email_key, None)

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


@router.post("/demo", response_model=TokenResponse)
async def create_or_get_demo_session(
    repo: BaseRepository = Depends(get_repository),
):
    """
    Provisions a live demo session for quick testing and recruiter evaluation.
    Can be disabled in production via ENABLE_DEMO_ENDPOINT=false.
    """
    if settings.AUTH_BACKEND == "cognito" or not settings.ENABLE_DEMO_ENDPOINT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo playground endpoint is disabled in production.",
        )
    """
    Frictionless Recruiter Demo Access (10-Second Test):
    Pre-provisions or retrieves a demo tenant user with a pre-configured
    Demo Security Gateway workspace, pre-generated Gateway API key,
    and simulated LLM response so recruiters can test the Attack Playground
    instantly with zero signup friction or external API key entry.
    """
    demo_email = "demo@gatekeep.ai"
    from app.core.security import generate_gateway_api_key
    demo_key_raw, key_hash, key_prefix = generate_gateway_api_key()

    # 1. Get or create demo user
    user = await repo.get_user_by_email(demo_email)
    if not user:
        user = User(
            id="usr_demo_recruiter",
            email=demo_email,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
        )
        user = await repo.create_user(user)

    # 2. Get or create demo workspace
    workspaces = await repo.list_workspaces_for_user(user.id)
    demo_ws = next((w for w in workspaces if w.name == "Demo Security Gateway"), None)
    if not demo_ws:
        demo_ws = Workspace(
            id="ws_demo_gateway",
            name="Demo Security Gateway",
            owner_id=user.id,
        )
        demo_ws = await repo.create_workspace(demo_ws)

    # 3. Ensure demo policy
    policy = await repo.get_policy(demo_ws.id)
    if not policy:
        policy = Policy(
            workspace_id=demo_ws.id,
            mode=PolicyMode.REDACT,
            block_injections=True,
            inspect_responses=True,
            rate_limit_rpm=120,
            upstream_base_url="https://demo.gatekeep.local/v1",
        )
        await repo.upsert_policy(policy)

    # 4. Ensure demo API key
    demo_api_key = ApiKey(workspace_id=demo_ws.id, name="Demo Access Key", key_hash=key_hash, prefix=key_prefix)
    await repo.create_api_key(demo_api_key)

    token = create_access_token(data={"sub": user.id, "email": user.email})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user.id,
            email=user.email,
            created_at=user.created_at,
        ),
        demo_workspace_id=demo_ws.id,
        demo_api_key=demo_key_raw,
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
