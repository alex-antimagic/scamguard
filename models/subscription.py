import uuid
from datetime import datetime, timezone

from extensions import db


TIER_FREE = 'free'
TIER_STARTER = 'starter'
TIER_PRO = 'pro'
TIER_ENTERPRISE = 'enterprise'

STATUS_ACTIVE = 'active'
STATUS_TRIALING = 'trialing'
STATUS_PAST_DUE = 'past_due'
STATUS_CANCELED = 'canceled'


class Subscription(db.Model):
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                        unique=True, nullable=False, index=True)

    stripe_subscription_id = db.Column(db.String(255), unique=True)
    stripe_price_id = db.Column(db.String(255))
    stripe_overage_item_id = db.Column(db.String(255))

    plan_tier = db.Column(db.String(20), nullable=False, default=TIER_FREE)
    status = db.Column(db.String(20), nullable=False, default=STATUS_ACTIVE)

    current_period_start = db.Column(db.DateTime)
    current_period_end = db.Column(db.DateTime)
    cancel_at_period_end = db.Column(db.Boolean, nullable=False, default=False)

    # Denormalized from plan_gating for fast reads
    scans_included = db.Column(db.Integer, nullable=False, default=100)
    overage_rate_cents = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    @property
    def is_paid(self):
        return self.plan_tier not in (TIER_FREE,)

    @property
    def is_active_paid(self):
        return self.is_paid and self.status in (STATUS_ACTIVE, STATUS_TRIALING)

    def __repr__(self):
        return f'<Subscription user={self.user_id} tier={self.plan_tier} status={self.status}>'
