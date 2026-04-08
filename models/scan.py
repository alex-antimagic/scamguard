import uuid
from datetime import datetime, timezone

from extensions import db


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    address_type = db.Column(db.String(20), nullable=False)
    address_raw = db.Column(db.String(500), nullable=False)
    address_normalized = db.Column(db.String(500), nullable=False, index=True)
    risk_score = db.Column(db.Integer)
    verdict = db.Column(db.String(20))
    findings_json = db.Column(db.Text)
    metadata_json = db.Column(db.Text)
    requester_ip = db.Column(db.String(45))
    analysis_time_ms = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))
