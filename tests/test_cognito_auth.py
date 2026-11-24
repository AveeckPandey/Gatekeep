"""Cognito control-plane authorization checks without external accounts."""

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings
from app.core import cognito


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
