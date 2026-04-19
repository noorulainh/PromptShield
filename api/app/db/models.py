from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False
    )

    events: Mapped[list["EventModel"]] = relationship(back_populates="session")
    mappings: Mapped[list["EncryptedMappingModel"]] = relationship(back_populates="session")


class EventModel(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    utility_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    leakage_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    request_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_input_masked: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    sanitized_text: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    predicted_label: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    pii_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    final_action: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    decision_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)

    session: Mapped[SessionModel] = relationship(back_populates="events")
    detections: Mapped[list["DetectionModel"]] = relationship(back_populates="event")


class DetectionModel(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True, nullable=False)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    start_idx: Mapped[int] = mapped_column(Integer, nullable=False)
    end_idx: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    strategy: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    placeholder: Mapped[str | None] = mapped_column(String(64), nullable=True)
    excerpt: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)

    event: Mapped[EventModel] = relationship(back_populates="detections")


class SanitizedOutputModel(Base):
    __tablename__ = "sanitized_outputs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True, nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    original_hash: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    sanitized_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class EncryptedMappingModel(Base):
    __tablename__ = "encrypted_mappings"
    __table_args__ = (UniqueConstraint("session_id", "raw_hash", name="uq_mapping_session_raw"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    raw_hash: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    placeholder: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), index=True
    )

    session: Mapped[SessionModel] = relationship(back_populates="mappings")


class TestResultModel(Base):
    __tablename__ = "test_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    suite_name: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    case_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    leakage_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    metrics_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class SettingModel(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False
    )
