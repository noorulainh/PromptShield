import re
from dataclasses import dataclass
from uuid import uuid4
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import decrypt_value, encrypt_value, hash_text, mask_value
from app.db.models import EncryptedMappingModel, SessionModel
from app.services.normalization import canonicalize_sensitive


@dataclass
class SessionRecallDetection:
    entity_type: str
    start: int
    end: int
    matched_text: str
    confidence: float
    strategy: str
    placeholder: str | None = None


@dataclass
class _Replacement:
    start: int
    end: int
    placeholder: str


PERSON_MAPPING_EXCLUDE_TOKENS = {
    "data",
    "science",
    "engineering",
    "medicine",
    "transfer",
    "passport",
    "account",
    "number",
    "phone",
    "email",
    "kitchen",
    "unauthorized",
    "kindly",
    "check",
    "tell",
    "me",
    "can",
    "you",
    "u",
    "what",
    "where",
    "who",
    "when",
    "why",
    "how",
    "here",
    "there",
    "doing",
    "working",
    "favourite",
    "favorite",
    "food",
    "applying",
    "msc",
    "bsc",
    "bs",
    "ms",
    "phd",
    "mba",
}
LATIN_PERSON_TOKEN_RE = re.compile(r"[a-z][a-z'\-]{1,30}", re.IGNORECASE)
URDU_PERSON_TOKEN_RE = re.compile(r"[\u0600-\u06FF]{2,}")


def _ranges_overlap(start: int, end: int, other_start: int, other_end: int) -> bool:
    return not (end <= other_start or start >= other_end)


def _load_session_mappings(db: Session, session_id: str) -> list[EncryptedMappingModel]:
    stmt = (
        select(EncryptedMappingModel)
        .where(EncryptedMappingModel.session_id == session_id)
        .order_by(EncryptedMappingModel.id.asc())
    )
    return db.scalars(stmt).all()


def _compile_mapping_pattern(raw_value: str) -> re.Pattern[str] | None:
    candidate = raw_value.strip()
    if len(candidate) < 2:
        return None

    escaped = re.escape(candidate)
    flags = re.UNICODE | (re.IGNORECASE if re.search(r"[A-Za-z]", candidate) else 0)

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9'’\- ]*[A-Za-z0-9]", candidate):
        return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", flags)

    return re.compile(escaped, flags)


def _person_value_is_plausible(raw_value: str, confidence: float | None = None, strategy: str | None = None) -> bool:
    candidate = raw_value.strip()
    if not candidate:
        return False

    if candidate.startswith("[") and candidate.endswith("]"):
        return False

    lowered = candidate.lower()
    latin_tokens = LATIN_PERSON_TOKEN_RE.findall(lowered)
    urdu_tokens = URDU_PERSON_TOKEN_RE.findall(candidate)

    if not latin_tokens and not urdu_tokens:
        return False

    if latin_tokens:
        if len(latin_tokens) > 3:
            return False
        if any(token in PERSON_MAPPING_EXCLUDE_TOKENS for token in latin_tokens):
            return False

    return True


def generate_session_id() -> str:
    return uuid4().hex[:24]


def ensure_session(db: Session, session_id: str, client_hash: str | None = None) -> SessionModel:
    session = db.get(SessionModel, session_id)
    if session is None:
        session = SessionModel(id=session_id, client_hash=client_hash)
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    if client_hash and session.client_hash != client_hash:
        session.client_hash = client_hash
        db.add(session)
        db.commit()

    return session


def _next_placeholder(db: Session, session_id: str, entity_type: str) -> str:
    count_stmt = select(func.count()).select_from(EncryptedMappingModel).where(
        EncryptedMappingModel.session_id == session_id,
        EncryptedMappingModel.entity_type == entity_type,
    )
    count = db.scalar(count_stmt) or 0
    return f"[{entity_type}_{count + 1}]"


def _get_or_create_mapping(db: Session, session_id: str, entity_type: str, raw_text: str) -> EncryptedMappingModel:
    normalized = canonicalize_sensitive(raw_text)
    raw_hash = hash_text(normalized, context=f"map:{session_id}")

    stmt = select(EncryptedMappingModel).where(
        EncryptedMappingModel.session_id == session_id,
        EncryptedMappingModel.raw_hash == raw_hash,
    )
    existing = db.scalar(stmt)
    if existing:
        return existing

    placeholder = _next_placeholder(db, session_id, entity_type)
    encrypted_value = encrypt_value(raw_text)
    mapping = EncryptedMappingModel(
        session_id=session_id,
        entity_type=entity_type,
        raw_hash=raw_hash,
        encrypted_value=encrypted_value,
        placeholder=placeholder,
    )
    db.add(mapping)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(stmt)
        if existing:
            return existing
        raise
    db.refresh(mapping)
    return mapping


def pseudonymize_text(db: Session, text: str, detections: list[Any], session_id: str) -> tuple[str, list[Any]]:
    replaced = text
    ordered = sorted(detections, key=lambda item: item.start)
    updated: list[Any] = list(ordered)
    replacements: list[_Replacement] = []

    # Allocate placeholders in reading order for stable, intuitive numbering.
    for detection in ordered:
        raw_value = text[detection.start : detection.end]
        if detection.entity_type == "PERSON":
            if not _person_value_is_plausible(
                raw_value,
                confidence=getattr(detection, "confidence", None),
                strategy=getattr(detection, "strategy", None),
            ):
                continue
        mapping = _get_or_create_mapping(db, session_id, detection.entity_type, raw_value)
        detection.placeholder = mapping.placeholder

        if detection.placeholder:
            replacements.append(_Replacement(start=detection.start, end=detection.end, placeholder=detection.placeholder))

    recall_candidates: list[tuple[int, int, EncryptedMappingModel, str]] = []
    for mapping in _load_session_mappings(db, session_id):
        raw_value = decrypt_value(mapping.encrypted_value)
        if mapping.entity_type == "PERSON" and not _person_value_is_plausible(raw_value):
            continue
        pattern = _compile_mapping_pattern(raw_value)
        if pattern is None:
            continue

        for match in pattern.finditer(text):
            start, end = match.span()
            recall_candidates.append((start, end, mapping, match.group(0)))

    for start, end, mapping, matched_text in sorted(
        recall_candidates,
        key=lambda item: (item[0], -(item[1] - item[0]), item[2].id),
    ):
        if any(_ranges_overlap(start, end, item.start, item.end) for item in replacements):
            continue

        replacements.append(_Replacement(start=start, end=end, placeholder=mapping.placeholder))
        updated.append(
            SessionRecallDetection(
                entity_type=mapping.entity_type,
                start=start,
                end=end,
                matched_text=matched_text,
                confidence=0.88,
                strategy="session_mapping_recall",
                placeholder=mapping.placeholder,
            )
        )

    for item in sorted(replacements, key=lambda value: value.start, reverse=True):
        replaced = f"{replaced[:item.start]}{item.placeholder}{replaced[item.end:]}"

    return replaced, sorted(updated, key=lambda item: item.start)


def list_session_mappings(db: Session, session_id: str, reveal_raw: bool = False) -> list[dict]:
    stmt = (
        select(EncryptedMappingModel)
        .where(EncryptedMappingModel.session_id == session_id)
        .order_by(EncryptedMappingModel.entity_type.asc(), EncryptedMappingModel.id.asc())
    )
    rows = db.scalars(stmt).all()
    payload: list[dict] = []

    for row in rows:
        raw_value = decrypt_value(row.encrypted_value)
        payload.append(
            {
                "id": row.id,
                "session_id": row.session_id,
                "entity_type": row.entity_type,
                "placeholder": row.placeholder,
                "masked_preview": raw_value if reveal_raw else mask_value(raw_value),
                "created_at": row.created_at,
            }
        )

    return payload


def delete_session_mappings(db: Session, session_id: str) -> int:
    stmt = select(EncryptedMappingModel).where(EncryptedMappingModel.session_id == session_id)
    rows = db.scalars(stmt).all()
    deleted = len(rows)
    for row in rows:
        db.delete(row)
    db.commit()
    return deleted
