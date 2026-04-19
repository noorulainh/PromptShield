import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import SettingModel

DEFAULT_APP_SETTINGS = {
    "risk_threshold": 0.6,
    "default_mode": "ml_based",
    "block_high_risk_output": True,
}


def get_json_setting(db: Session, key: str, default: dict | list | None = None):
    row = db.get(SettingModel, key)
    if not row:
        return default
    try:
        return json.loads(row.value_json)
    except json.JSONDecodeError:
        return default


def set_json_setting(db: Session, key: str, value: dict | list) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    row = db.get(SettingModel, key)
    if row:
        row.value_json = payload
    else:
        row = SettingModel(key=key, value_json=payload)
        db.add(row)
    db.commit()


def get_app_settings(db: Session) -> dict:
    current = get_json_setting(db, "app_settings", DEFAULT_APP_SETTINGS)
    if not current:
        current = DEFAULT_APP_SETTINGS
    for key, value in DEFAULT_APP_SETTINGS.items():
        current.setdefault(key, value)

    if current.get("default_mode") not in {"ml_based", "heuristic_based"}:
        current["default_mode"] = "ml_based"

    return current


def update_app_settings(db: Session, updates: dict) -> dict:
    current = get_app_settings(db)
    current.update(updates)
    set_json_setting(db, "app_settings", current)
    return current


def list_settings(db: Session) -> dict:
    stmt = select(SettingModel)
    rows = db.scalars(stmt).all()
    out: dict[str, str] = {}
    for row in rows:
        out[row.key] = row.value_json
    return out
