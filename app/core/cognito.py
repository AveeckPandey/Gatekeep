"""Cognito user-pool authentication for the dashboard control plane."""

import asyncio

import boto3
import jwt
from jwt import PyJWKClient

from app.config import settings


def cognito_client():
    return boto3.client("cognito-idp", region_name=settings.COGNITO_REGION)


def verify_cognito_access_token(token: str) -> dict:
    """Verify signature and all claims used to authorize API requests."""
    issuer = f"https://cognito-idp.{settings.COGNITO_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}"
    key = PyJWKClient(f"{issuer}/.well-known/jwks.json").get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=issuer, options={"verify_aud": False})
    if claims.get("token_use") != "access" or claims.get("client_id") != settings.COGNITO_APP_CLIENT_ID:
        raise jwt.InvalidTokenError("Wrong token type or app client")
    if not claims.get("sub"):
        raise jwt.InvalidTokenError("Missing subject")
    return claims


async def sign_up(email: str, password: str) -> dict:
    return await asyncio.to_thread(
        cognito_client().sign_up,
        ClientId=settings.COGNITO_APP_CLIENT_ID,
        Username=email,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": email}],
    )


async def confirm_sign_up(email: str, code: str) -> None:
    await asyncio.to_thread(
        cognito_client().confirm_sign_up,
        ClientId=settings.COGNITO_APP_CLIENT_ID,
        Username=email,
        ConfirmationCode=code,
    )


async def authenticate(email: str, password: str) -> dict:
    return await asyncio.to_thread(
        cognito_client().initiate_auth,
        ClientId=settings.COGNITO_APP_CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": password},
    )
