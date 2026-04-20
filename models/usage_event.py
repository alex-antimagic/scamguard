from datetime import datetime, timezone

from extensions import db


class UsageEvent(db.Model):
    __tablename__ = 'usage_events'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_keys.id'), index=True)

    event_type = db.Column(db.String(32), nullable=False, default='scan')
    source = db.Column(db.String(16), nullable=False)  # 'portal' | 'api'
    address_type = db.Column(db.String(16))

    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    ip_hash = db.Column(db.String(64), index=True)

    created_at = db.Column(db.DateTime, nullable=False, index=True,
                           default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<UsageEvent {self.source}/{self.event_type} user={self.user_id}>'
