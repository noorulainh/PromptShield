from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import encrypt_value, hash_text
from app.db.base import Base
from app.db.models import EncryptedMappingModel
from app.services.detector import detect_sensitive_entities
from app.services.normalization import canonicalize_sensitive
from app.services.pseudonymizer import ensure_session, list_session_mappings, pseudonymize_text


def _make_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return session_local()


def test_session_consistent_placeholders() -> None:
    db = _make_db()
    session_id = "demo-session"
    ensure_session(db, session_id)

    text1 = "My name is Ali Khan and phone is 0300-5556677"
    text2 = "Ali Khan contacted again from number 0300 5556677"

    d1 = detect_sensitive_entities(text1)
    sanitized1, updated1 = pseudonymize_text(db, text1, d1, session_id)

    d2 = detect_sensitive_entities(text2)
    sanitized2, updated2 = pseudonymize_text(db, text2, d2, session_id)

    person_placeholder1 = next(item.placeholder for item in updated1 if item.entity_type == "PERSON")
    person_placeholder2 = next(item.placeholder for item in updated2 if item.entity_type == "PERSON")
    phone_placeholder1 = next(item.placeholder for item in updated1 if item.entity_type == "PHONE")
    phone_placeholder2 = next(item.placeholder for item in updated2 if item.entity_type == "PHONE")

    assert person_placeholder1 == person_placeholder2
    assert phone_placeholder1 == phone_placeholder2
    assert person_placeholder1 in sanitized1 and person_placeholder2 in sanitized2
    assert phone_placeholder1 in sanitized1 and phone_placeholder2 in sanitized2

    mappings = list_session_mappings(db, session_id)
    assert len(mappings) >= 2


def test_placeholders_do_not_log_raw_by_default() -> None:
    db = _make_db()
    session_id = "mask-session"
    ensure_session(db, session_id)

    text = "Email is secret.person@example.com"
    detections = detect_sensitive_entities(text)
    pseudonymize_text(db, text, detections, session_id)

    mappings = list_session_mappings(db, session_id, reveal_raw=False)
    assert "@" not in mappings[0]["masked_preview"]


def test_placeholders_are_numbered_left_to_right() -> None:
    db = _make_db()
    session_id = "ordering-session"
    ensure_session(db, session_id)

    text = "Mera account number 009988776655 hai aur IBAN PK36SCBL0000001123456702"
    detections = detect_sensitive_entities(text)
    sanitized, updated = pseudonymize_text(db, text, detections, session_id)

    financial = [item for item in updated if item.entity_type == "FINANCIAL"]

    assert len(financial) >= 2
    assert financial[0].matched_text == "009988776655"
    assert financial[0].placeholder == "[FINANCIAL_1]"
    assert financial[1].matched_text == "PK36SCBL0000001123456702"
    assert financial[1].placeholder == "[FINANCIAL_2]"
    assert "[FINANCIAL_1]" in sanitized
    assert "[FINANCIAL_2]" in sanitized


def test_existing_mapping_recalled_when_fresh_detection_misses() -> None:
    db = _make_db()
    session_id = "mapping-recall-session"
    ensure_session(db, session_id)

    first_text = "my name is ali"
    first_detections = detect_sensitive_entities(first_text)
    first_sanitized, _ = pseudonymize_text(db, first_text, first_detections, session_id)

    second_text = "where is ali?"
    second_detections = detect_sensitive_entities(second_text)
    second_sanitized, second_updated = pseudonymize_text(db, second_text, second_detections, session_id)

    assert "[PERSON_1]" in first_sanitized
    assert "[PERSON_1]" in second_sanitized
    assert "ali" not in second_sanitized.lower()
    assert any(getattr(item, "strategy", "") == "session_mapping_recall" for item in second_updated)


def test_legacy_bad_person_mapping_is_not_recalled() -> None:
    db = _make_db()
    session_id = "legacy-bad-mapping-session"
    ensure_session(db, session_id)

    bad_value = "Data Science"
    db.add(
        EncryptedMappingModel(
            session_id=session_id,
            entity_type="PERSON",
            raw_hash=hash_text(canonicalize_sensitive(bad_value), context=f"map:{session_id}"),
            encrypted_value=encrypt_value(bad_value),
            placeholder="[PERSON_6]",
        )
    )
    db.commit()

    text = (
        "Assalam o Alaikum, this is Noor Fatima applying for MSc Data Science. "
        "Email: noor.fatima@example.edu, Passport: AB1234567."
    )
    detections = detect_sensitive_entities(text)
    sanitized, updated = pseudonymize_text(db, text, detections, session_id)

    assert "MSc Data Science" in sanitized
    assert "[PERSON_6]" not in sanitized
    assert not any(getattr(item, "strategy", "") == "session_mapping_recall" and item.matched_text == "Data Science" for item in updated)
