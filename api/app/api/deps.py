from collections.abc import Generator

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_text, parse_admin_token
from app.db.session import get_db as session_get_db


settings = get_settings()


def get_db() -> Generator[Session, None, None]:
    yield from session_get_db()


def get_client_hash(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return hash_text(f"{ip}|{user_agent[:80]}", context="client")


def require_admin(request: Request):
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin login required")
    payload = parse_admin_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin session")
    return payload


def require_csrf(request: Request):
    csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
    csrf_header = request.headers.get("x-csrf-token")
    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch")
    return True
