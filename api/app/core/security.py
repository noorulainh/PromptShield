import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet
from itsdangerous import BadSignature, URLSafeSerializer

from app.core.config import get_settings


def _derive_fernet_key(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8")


@lru_cache
def get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.MAPPING_ENCRYPTION_KEY.strip() or _derive_fernet_key(settings.APP_SECRET)
    return Fernet(key.encode("utf-8"))


@lru_cache
def get_serializer() -> URLSafeSerializer:
    settings = get_settings()
    return URLSafeSerializer(settings.APP_SECRET, salt="promptshield-admin")


def hash_text(value: str, context: str = "default") -> str:
    settings = get_settings()
    payload = f"{context}:{value}".encode("utf-8")
    return hmac.new(settings.APP_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def verify_admin_password(password: str) -> bool:
    settings = get_settings()
    return secure_compare(password, settings.ADMIN_PASSWORD)


def create_admin_token() -> str:
    serializer = get_serializer()
    payload = {
        "role": "admin",
        "issued_at": datetime.now(UTC).isoformat(),
    }
    return serializer.dumps(payload)


def parse_admin_token(token: str) -> dict[str, Any] | None:
    serializer = get_serializer()
    try:
        payload = serializer.loads(token)
    except BadSignature:
        return None
    if payload.get("role") != "admin":
        return None
    return payload


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def encrypt_value(raw_value: str) -> str:
    fernet = get_fernet()
    return fernet.encrypt(raw_value.encode("utf-8")).decode("utf-8")


def decrypt_value(encrypted_value: str) -> str:
    fernet = get_fernet()
    return fernet.decrypt(encrypted_value.encode("utf-8")).decode("utf-8")


def mask_value(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return ""
    if len(stripped) <= 4:
        return "*" * len(stripped)
    return f"{stripped[:2]}{'*' * max(1, len(stripped) - 4)}{stripped[-2:]}"
