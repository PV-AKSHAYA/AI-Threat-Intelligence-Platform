"""
Database models using SQLAlchemy with SQLite
"""
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

DATABASE_URL = "sqlite:///./threat_intel.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    input_type = Column(String)
    input_preview = Column(String)
    risk_score = Column(Integer)
    risk_level = Column(String)
    iocs_count = Column(Integer, default=0)
    mitre_count = Column(Integer, default=0)

    # Full JSON blobs
    iocs_json = Column(Text, default="[]")
    enrichment_json = Column(Text, default="{}")
    mitre_mapping_json = Column(Text, default="[]")
    risk_factors_json = Column(Text, default="[]")
    ai_report_json = Column(Text, default="{}")
    detection_rules_json = Column(Text, default="{}")

    def to_dict(self):
        return {
            "analysis_id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "input_type": self.input_type,
            "input_preview": self.input_preview,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "iocs_count": self.iocs_count,
            "mitre_count": self.mitre_count,
            "iocs": json.loads(self.iocs_json or "[]"),
            "enrichment": json.loads(self.enrichment_json or "{}"),
            "mitre_mapping": json.loads(self.mitre_mapping_json or "[]"),
            "risk_factors": json.loads(self.risk_factors_json or "[]"),
            "ai_report": json.loads(self.ai_report_json or "{}"),
            "detection_rules": json.loads(self.detection_rules_json or "{}"),
        }

    def to_summary(self):
        return {
            "analysis_id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "input_type": self.input_type,
            "input_preview": self.input_preview,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "iocs_count": self.iocs_count,
            "mitre_count": self.mitre_count,
        }
