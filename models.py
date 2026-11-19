from sqlalchemy import Column, Integer, String, Float, Boolean, Text, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from backend.app.database import Base


class DatasetMetadata(Base):
    __tablename__ = "dataset_metadata"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(50), primary_key=True, index=True)  # e.g. INC-2026-0147
    key = Column(String(50), nullable=False)  # ransomware, phishing, etc.
    title = Column(String(255), nullable=False)
    discovered = Column(BigInteger, nullable=False)  # Unix epoch timestamp in ms
    pii = Column(Boolean, default=False)
    eu = Column(Boolean, default=False)
    notes = Column(Text, default="")
    attack_category = Column(String(100), default="")
    severity = Column(String(50), default="Critical")
    view_phase = Column(Integer, default=1)
    owner = Column(String(100), default="SOC Lead")
    created_at = Column(BigInteger, nullable=False)

    # Relationships
    evidence_logs = relationship("EvidenceLog", back_populates="incident", cascade="all, delete-orphan")
    steps = relationship("PlaybookStep", back_populates="incident", cascade="all, delete-orphan")


class EvidenceLog(Base):
    __tablename__ = "evidence_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), ForeignKey("incidents.id"), nullable=False, index=True)
    ts = Column(BigInteger, nullable=False)
    actor = Column(String(100), nullable=False)
    action = Column(Text, nullable=False)
    extra = Column(Text, default="")
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)

    incident = relationship("Incident", back_populates="evidence_logs")


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"

    id = Column(String(50), primary_key=True)  # e.g. INC-2026-0147-p1s0
    incident_id = Column(String(50), ForeignKey("incidents.id"), nullable=False, index=True)
    phase = Column(Integer, nullable=False)  # 0: Prep, 1: Detection, 2: Containment, 3: Post
    text = Column(Text, nullable=False)
    src = Column(String(100), default="")
    atk = Column(String(50), default="")
    done = Column(Boolean, default=False)
    by = Column(String(100), nullable=True)

    incident = relationship("Incident", back_populates="steps")
