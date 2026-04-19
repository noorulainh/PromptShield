from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_csrf
from app.core.config import get_settings
from app.core.security import create_admin_token, new_csrf_token, verify_admin_password
from app.db.models import EventModel, SessionModel
from app.db.session import get_db
from app.schemas.api import AuthStatus, LoginRequest, LoginResponse, MappingItem, SettingsPayload, SettingsResponse
from app.services.pseudonymizer import delete_session_mappings, list_session_mappings
from app.services.settings_store import get_app_settings, update_app_settings

router = APIRouter()
settings = get_settings()


@router.post("/auth/login", response_model=LoginResponse)
def admin_login(payload: LoginRequest, response: Response) -> LoginResponse:
    if not verify_admin_password(payload.password):
        return LoginResponse(authenticated=False, csrf_token=None)

    token = create_admin_token()
    csrf_token = new_csrf_token()

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return LoginResponse(authenticated=True, csrf_token=csrf_token)


@router.post("/auth/logout", response_model=LoginResponse)
def admin_logout(response: Response) -> LoginResponse:
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    response.delete_cookie(settings.CSRF_COOKIE_NAME)
    return LoginResponse(authenticated=False, csrf_token=None)


@router.get("/auth/me", response_model=AuthStatus)
def admin_me(_admin=Depends(require_admin)) -> AuthStatus:
    return AuthStatus(authenticated=True, role="admin")


@router.get("/settings", response_model=SettingsResponse)
def get_settings_endpoint(_admin=Depends(require_admin), db: Session = Depends(get_db)) -> SettingsResponse:
    return SettingsResponse(settings=SettingsPayload(**get_app_settings(db)))


@router.put("/settings", response_model=SettingsResponse)
def update_settings_endpoint(
    payload: SettingsPayload,
    _admin=Depends(require_admin),
    _csrf=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SettingsResponse:
    updated = update_app_settings(db, payload.model_dump())
    return SettingsResponse(settings=SettingsPayload(**updated))


@router.get("/mappings/{session_id}", response_model=list[MappingItem])
def get_mappings(
    session_id: str,
    reveal_raw: bool = Query(default=False),
    _admin=Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[dict]:
    return list_session_mappings(db, session_id, reveal_raw=reveal_raw)


@router.delete("/mappings/{session_id}")
def delete_mappings(
    session_id: str,
    _admin=Depends(require_admin),
    _csrf=Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict:
    deleted = delete_session_mappings(db, session_id)
    return {"session_id": session_id, "deleted": deleted}


@router.get("/sessions")
def list_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    _admin=Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[dict]:
    sessions = db.scalars(select(SessionModel).order_by(desc(SessionModel.last_seen)).limit(limit)).all()
    counts = {
        row[0]: row[1]
        for row in db.execute(
            select(EventModel.session_id, func.count(EventModel.id)).group_by(EventModel.session_id)
        ).all()
    }
    return [
        {
            "session_id": item.id,
            "created_at": item.created_at,
            "last_seen": item.last_seen,
            "event_count": counts.get(item.id, 0),
        }
        for item in sessions
    ]
