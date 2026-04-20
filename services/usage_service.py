"""Usage tracking + quota enforcement.

Caller model:
- Anonymous: identified by IP hash, daily quota (ANON_DAILY_QUOTA).
- Free-tier authenticated: monthly quota, hard cap (no overage).
- Paid authenticated: monthly quota, overage allowed (billed via Stripe).
"""
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from flask import current_app

from extensions import db
from models.usage_event import UsageEvent
from models.subscription import (Subscription, TIER_FREE, STATUS_ACTIVE, STATUS_TRIALING)
from services.plan_gating import ANON_DAILY_QUOTA


@dataclass
class Caller:
    """Represents who is making the request."""
    user_id: Optional[int] = None
    api_key_id: Optional[int] = None
    ip: Optional[str] = None
    ip_hash: Optional[str] = None
    source: str = 'portal'  # 'portal' | 'api'
    subscription: Optional[Subscription] = None

    @property
    def is_anonymous(self):
        return self.user_id is None


def hash_ip(ip: str, salt: str = '') -> str:
    return hashlib.sha256(f'{salt}{ip}'.encode()).hexdigest()[:32]


def build_caller_from_request(request, g_user=None, g_api_key=None) -> Caller:
    """Build a Caller from Flask request + optional authenticated user/api_key."""
    salt = current_app.config.get('SECRET_KEY', '')[:16]
    ip = request.remote_addr or ''
    ip_hashed = hash_ip(ip, salt)

    if g_user:
        return Caller(
            user_id=g_user.id,
            api_key_id=g_api_key.id if g_api_key else None,
            ip=ip,
            ip_hash=ip_hashed,
            source='api' if g_api_key else 'portal',
            subscription=g_user.subscription,
        )

    return Caller(
        ip=ip,
        ip_hash=ip_hashed,
        source='portal',
    )


@dataclass
class QuotaResult:
    allowed: bool
    reason: str = ''      # machine-readable: 'ok', 'anon_cap', 'free_cap', 'overage'
    remaining: Optional[int] = None
    limit: Optional[int] = None


def _period_start(sub: Subscription) -> datetime:
    if sub and sub.current_period_start:
        return sub.current_period_start
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _anon_day_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def check_quota(caller: Caller) -> QuotaResult:
    """Check whether this caller can make another scan request.

    Returns QuotaResult with allowed=False and reason if blocked.
    Does NOT consume quota — use record_usage() after the scan runs.
    """
    if caller.is_anonymous:
        since = _anon_day_start()
        count = UsageEvent.query.filter(
            UsageEvent.user_id.is_(None),
            UsageEvent.ip_hash == caller.ip_hash,
            UsageEvent.created_at >= since,
        ).count()
        if count >= ANON_DAILY_QUOTA:
            return QuotaResult(allowed=False, reason='anon_cap',
                               remaining=0, limit=ANON_DAILY_QUOTA)
        return QuotaResult(allowed=True, reason='ok',
                           remaining=ANON_DAILY_QUOTA - count,
                           limit=ANON_DAILY_QUOTA)

    sub = caller.subscription
    if not sub:
        # Shouldn't happen — every user gets a sub at registration — but fail closed
        return QuotaResult(allowed=False, reason='no_subscription')

    since = _period_start(sub)
    count = UsageEvent.query.filter(
        UsageEvent.user_id == caller.user_id,
        UsageEvent.created_at >= since,
    ).count()

    # Free tier and inactive paid = hard cap
    if sub.plan_tier == TIER_FREE or sub.status not in (STATUS_ACTIVE, STATUS_TRIALING):
        if count >= (sub.scans_included or 0):
            return QuotaResult(allowed=False, reason='free_cap',
                               remaining=0, limit=sub.scans_included)
        return QuotaResult(allowed=True, reason='ok',
                           remaining=(sub.scans_included or 0) - count,
                           limit=sub.scans_included)

    # Paid tier: overage allowed, always return allowed (Stripe bills the diff)
    remaining = max(0, (sub.scans_included or 0) - count)
    return QuotaResult(allowed=True,
                       reason='overage' if remaining == 0 else 'ok',
                       remaining=remaining,
                       limit=sub.scans_included)


def record_usage(caller: Caller, scan_id: Optional[int] = None,
                 address_type: Optional[str] = None,
                 event_type: str = 'scan') -> UsageEvent:
    """Persist a UsageEvent and increment the api_key counter if applicable."""
    event = UsageEvent(
        user_id=caller.user_id,
        api_key_id=caller.api_key_id,
        event_type=event_type,
        source=caller.source,
        address_type=address_type,
        scan_id=scan_id,
        ip_hash=caller.ip_hash,
    )
    db.session.add(event)

    if caller.api_key_id:
        from models.api_key import ApiKey
        key = ApiKey.query.get(caller.api_key_id)
        if key:
            key.request_count = (key.request_count or 0) + 1
            key.last_used_at = datetime.now(timezone.utc)

    db.session.commit()
    return event
