import uuid
from datetime import datetime, timezone

from extensions import db


class ScamReport(db.Model):
    __tablename__ = 'scam_reports'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    address_type = db.Column(db.String(20), nullable=False)
    address_raw = db.Column(db.String(500), nullable=False)
    address_normalized = db.Column(db.String(500), nullable=False, index=True)
    reporter_ip = db.Column(db.String(45))
    reporter_fingerprint = db.Column(db.String(64))
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))
