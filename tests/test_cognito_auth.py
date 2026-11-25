"""Cognito control-plane authorization checks without external accounts."""

import jwt
import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.config import settings
from app.core import cognito
from app.models.user import UserLoginRequest
from app.routes import auth


def test_cognito_token_claims(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(settings, "COGNITO_REGION", "us-east-1")
    monkeypatch.setattr(settings, "COGNITO_USER_POOL_ID", "us-east-1_test")
    monkeypatch.setattr(settings, "COGNITO_APP_CLIENT_ID", "test-client")
    monkeypatch.setattr(cognito, "PyJWKClient", lambda _: type("Keys", (), {"get_signing_key_from_jwt": lambda self, token: type("Key", (), {"key": private_key.public_key()})()})())
    issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test"

    def token(**overrides):
        claims = {"sub": "user-1", "iss": issuer, "client_id": "test-client", "token_use": "access", "exp": 4102444800}
        claims.update(overrides)
        return jwt.encode(claims, private_key, algorithm="RS256")

    assert cognito.verify_cognito_access_token(token())["sub"] == "user-1"
    with pytest.raises(jwt.InvalidTokenError):
        cognito.verify_cognito_access_token(token(client_id="another-client"))
    with pytest.raises(jwt.InvalidTokenError):
        cognito.verify_cognito_access_token(token(token_use="id"))
    with pytest.raises(jwt.InvalidTokenError):
        cognito.verify_cognito_access_token(token(iss="https://attacker.example"))


@pytest.mark.asyncio
@pytest.mark.parametrize("error_code", ["UserNotFoundException", "NotAuthorizedException"])
async def test_cognito_login_does_not_reveal_account_existence(monkeypatch, error_code):
    monkeypatch.setattr(settings, "AUTH_BACKEND", "cognito")

    async def reject_login(_email, _password):
        raise ClientError({"Error": {"Code": error_code, "Message": "Rejected"}}, "InitiateAuth")

    monkeypatch.setattr(cognito, "authenticate", reject_login)
    with pytest.raises(HTTPException) as result:
        await auth.login(UserLoginRequest(email="unknown@example.com", password="invalid"), repo=None)

    assert result.value.status_code == 401
    assert result.value.detail == "Invalid email or password"


@pytest.mark.asyncio
async def test_resend_confirmation_returns_masked_delivery_destination(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_BACKEND", "cognito")

    async def resend(_email):
        return {"CodeDeliveryDetails": {"Destination": "a***@e***.com", "DeliveryMedium": "EMAIL"}}

    monkeypatch.setattr(cognito, "resend_confirmation_code", resend)
    response = await auth.resend_confirmation(auth.ResendConfirmationRequest(email="pending@example.com"))

    assert response == {
        "message": "A new confirmation code was sent.",
        "destination": "a***@e***.com",
    }


@pytest.mark.asyncio
async def test_resend_confirmation_reports_cognito_throttling(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_BACKEND", "cognito")

    async def throttled(_email):
        raise ClientError({"Error": {"Code": "LimitExceededException", "Message": "Limit exceeded"}}, "ResendConfirmationCode")

    monkeypatch.setattr(cognito, "resend_confirmation_code", throttled)
    with pytest.raises(HTTPException) as result:
        await auth.resend_confirmation(auth.ResendConfirmationRequest(email="pending@example.com"))

    assert result.value.status_code == 429
