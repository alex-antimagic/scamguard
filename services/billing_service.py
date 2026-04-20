"""Stripe billing integration — checkout, portal, webhooks, overage reporting.

Gracefully degrades when Stripe keys aren't configured (returns None).
"""
import logging
from datetime import datetime, timezone

from flask import current_app

from extensions import db
from models.subscription import (Subscription, TIER_FREE, TIER_STARTER, TIER_PRO,
                                  STATUS_ACTIVE, STATUS_TRIALING, STATUS_PAST_DUE,
                                  STATUS_CANCELED)
from services.plan_gating import get_plan

logger = logging.getLogger(__name__)


def _get_stripe():
    key = current_app.config.get('STRIPE_SECRET_KEY')
    if not key:
        return None
    try:
        import stripe
        stripe.api_key = key
        return stripe
    except ImportError:
        return None


def stripe_configured():
    return bool(current_app.config.get('STRIPE_SECRET_KEY'))


def _price_id_for_tier(tier):
    price_map = {
        TIER_STARTER: current_app.config.get('STRIPE_STARTER_PRICE_ID'),
        TIER_PRO: current_app.config.get('STRIPE_PRO_PRICE_ID'),
    }
    return price_map.get(tier)


def _tier_for_price_id(price_id):
    if not price_id:
        return None
    if price_id == current_app.config.get('STRIPE_PRO_PRICE_ID'):
        return TIER_PRO
    if price_id == current_app.config.get('STRIPE_STARTER_PRICE_ID'):
        return TIER_STARTER
    return None


def _status_map(stripe_status):
    return {
        'active': STATUS_ACTIVE,
        'trialing': STATUS_TRIALING,
        'past_due': STATUS_PAST_DUE,
        'unpaid': STATUS_PAST_DUE,
        'incomplete': STATUS_PAST_DUE,
        'incomplete_expired': STATUS_CANCELED,
        'canceled': STATUS_CANCELED,
    }.get(stripe_status, STATUS_ACTIVE)


def _ensure_customer(user, stripe):
    if user.stripe_customer_id:
        return user.stripe_customer_id
    customer = stripe.Customer.create(
        email=user.email,
        name=user.name or None,
        metadata={'user_id': str(user.id), 'user_token': user.token},
    )
    user.stripe_customer_id = customer.id
    db.session.commit()
    return customer.id


def create_checkout_session(user, plan_tier, success_url, cancel_url):
    """Create a Stripe Checkout session for the given plan."""
    stripe = _get_stripe()
    if not stripe:
        return None

    price_id = _price_id_for_tier(plan_tier)
    if not price_id:
        logger.error('No Stripe price ID configured for tier=%s', plan_tier)
        return None

    try:
        customer_id = _ensure_customer(user, stripe)
        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode='subscription',
            line_items=[{'price': price_id, 'quantity': 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            allow_promotion_codes=True,
            subscription_data={
                'metadata': {'user_id': str(user.id), 'user_token': user.token},
            },
            metadata={'user_id': str(user.id), 'user_token': user.token},
        )
        return session
    except Exception:
        logger.exception('Failed to create checkout session for user %s', user.id)
        return None


def create_portal_session(user, return_url):
    stripe = _get_stripe()
    if not stripe or not user.stripe_customer_id:
        return None
    try:
        return stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=return_url,
        )
    except Exception:
        logger.exception('Failed to create portal session for user %s', user.id)
        return None


def _sync_subscription_from_stripe_object(user, stripe_sub):
    """Update the local Subscription row from a Stripe Subscription object."""
    sub = user.subscription
    if not sub:
        return None

    sub.stripe_subscription_id = stripe_sub.get('id')
    sub.status = _status_map(stripe_sub.get('status'))
    sub.cancel_at_period_end = bool(stripe_sub.get('cancel_at_period_end'))

    cps = stripe_sub.get('current_period_start')
    cpe = stripe_sub.get('current_period_end')
    if cps:
        sub.current_period_start = datetime.fromtimestamp(cps, tz=timezone.utc)
    if cpe:
        sub.current_period_end = datetime.fromtimestamp(cpe, tz=timezone.utc)

    items = (stripe_sub.get('items') or {}).get('data') or []
    if items:
        # Find plan item (recurring, not metered)
        for item in items:
            price = item.get('price') or {}
            price_id = price.get('id')
            tier = _tier_for_price_id(price_id)
            if tier:
                sub.plan_tier = tier
                sub.stripe_price_id = price_id
                plan = get_plan(tier)
                sub.scans_included = plan['scans_included']
                sub.overage_rate_cents = int(plan['overage_rate_cents_per_unit'] * 100)
                break

    sub.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return sub


def handle_webhook(payload, sig_header):
    """Verify + process a Stripe webhook event."""
    stripe = _get_stripe()
    if not stripe:
        return None, False

    webhook_secret = current_app.config.get('STRIPE_WEBHOOK_SECRET')
    if not webhook_secret:
        logger.error('STRIPE_WEBHOOK_SECRET not configured')
        return None, False

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        logger.warning('Webhook signature verification failed: %s', e)
        return None, False

    event_type = event['type']
    obj = event['data']['object']

    from models.user import User

    if event_type == 'checkout.session.completed':
        user_id = (obj.get('metadata') or {}).get('user_id')
        sub_id = obj.get('subscription')
        if user_id and sub_id:
            user = db.session.get(User, int(user_id))
            if user:
                stripe_sub = stripe.Subscription.retrieve(sub_id)
                _sync_subscription_from_stripe_object(user, stripe_sub)
                logger.info('Activated subscription for user %s', user.id)

    elif event_type in ('customer.subscription.updated', 'customer.subscription.created'):
        sub_id = obj.get('id')
        user_id = (obj.get('metadata') or {}).get('user_id')
        user = None
        if user_id:
            user = db.session.get(User, int(user_id))
        if not user:
            local_sub = Subscription.query.filter_by(stripe_subscription_id=sub_id).first()
            user = local_sub.user if local_sub else None
        if user:
            _sync_subscription_from_stripe_object(user, obj)

    elif event_type == 'customer.subscription.deleted':
        sub_id = obj.get('id')
        local_sub = Subscription.query.filter_by(stripe_subscription_id=sub_id).first()
        if local_sub:
            free = get_plan(TIER_FREE)
            local_sub.plan_tier = TIER_FREE
            local_sub.status = STATUS_ACTIVE
            local_sub.stripe_subscription_id = None
            local_sub.stripe_price_id = None
            local_sub.scans_included = free['scans_included']
            local_sub.overage_rate_cents = 0
            db.session.commit()
            logger.info('Downgraded user %s to free tier', local_sub.user_id)

    elif event_type == 'invoice.payment_failed':
        customer_id = obj.get('customer')
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user and user.subscription:
            user.subscription.status = STATUS_PAST_DUE
            db.session.commit()
            logger.warning('Payment failed for user %s', user.id)

    return event_type, True
