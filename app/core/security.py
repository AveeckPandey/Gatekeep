import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def hash_password(password: str) -> str:
    """Hashes a password with bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.PyJWTError:
        return None


def get_fernet_cipher() -> Fernet:
    """Initializes Fernet cipher with configured encryption key."""
    key = settings.ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypts a plaintext secret using Fernet (AES-128-CBC + HMAC-SHA256)."""
    if not plaintext:
        return ""
    cipher = get_fernet_cipher()
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypts an encrypted secret using Fernet."""
    if not ciphertext:
        return ""
    try:
        cipher = get_fernet_cipher()
        return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Failed to decrypt secret: invalid token or encryption key")


def hash_api_key(key: str) -> str:
    """Computes SHA-256 hash of a Gateway API key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_gateway_api_key() -> Tuple[str, str, str]:
    """
    Generates a new secure Gateway API key.
    Returns:
        (plaintext_key, key_hash, prefix)
    The plaintext_key is shown ONLY ONCE to the user upon creation.
    Only key_hash and prefix are stored in the database.
    """
    random_part = secrets.token_urlsafe(32).replace("-", "").replace("_", "")[:32]
    plaintext_key = f"gw_live_{random_part}"
    key_hash = hash_api_key(plaintext_key)
    prefix = f"{plaintext_key[:12]}..."
    return plaintext_key, key_hash, prefix
