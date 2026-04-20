import secrets
import uuid
from datetime import datetime, timezone

import bcrypt

from extensions import db


KEY_PREFIX = 'sg_live_'


class ApiKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    name = db.Column(db.String(120), nullable=False)
    key_prefix = db.Column(db.String(24), nullable=False, index=True)
    key_hash = db.Column(db.String(255), nullable=False)

    last_used_at = db.Column(db.DateTime)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    revoked_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    @classmethod
    def generate(cls, user, name):
        """Generate a new API key. Returns (api_key_instance, plaintext_key).

        The plaintext key is returned once and never stored.
        """
        raw = secrets.token_urlsafe(32)
        full_key = f'{KEY_PREFIX}{raw}'
        prefix = full_key[:16]
        key_hash = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()

        api_key = cls(
            user_id=user.id,
            name=name,
            key_prefix=prefix,
            key_hash=key_hash,
        )
        return api_key, full_key

    def verify(self, candidate):
        """Check a plaintext key against the stored hash."""
        if not self.is_active:
            return False
        try:
            return bcrypt.checkpw(candidate.encode(), self.key_hash.encode())
        except (ValueError, AttributeError):
            return False

    def revoke(self):
        self.is_active = False
        self.revoked_at = datetime.now(timezone.utc)

    def __repr__(self):
        return f'<ApiKey {self.key_prefix}... ({self.name})>'
