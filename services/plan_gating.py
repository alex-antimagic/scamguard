"""Plan tier → feature/quota mapping.

Single source of truth for what each tier includes. Consumed by:
- usage_service (quota checks)
- billing_service (on subscription update)
- dashboard templates (display)
"""

from models.subscription import TIER_FREE, TIER_STARTER, TIER_PRO, TIER_ENTERPRISE


PLAN_FEATURES = {
    TIER_FREE: {
        'display_name': 'Free',
        'price_monthly_cents': 0,
        'scans_included': 100,
        'max_api_keys': 1,
        'overage_rate_cents_per_unit': 0,  # hard cap — no overage allowed
        'allow_overage': False,
        'priority_support': False,
    },
    TIER_STARTER: {
        'display_name': 'Starter',
        'price_monthly_cents': 2900,
        'scans_included': 10_000,
        'max_api_keys': 3,
        'overage_rate_cents_per_unit': 1,  # $0.01 per scan over
        'allow_overage': True,
        'priority_support': False,
    },
    TIER_PRO: {
        'display_name': 'Pro',
        'price_monthly_cents': 19900,
        'scans_included': 100_000,
        'max_api_keys': 10,
        'overage_rate_cents_per_unit': 0.5,  # $0.005 per scan over
        'allow_overage': True,
        'priority_support': True,
    },
    TIER_ENTERPRISE: {
        'display_name': 'Enterprise',
        'price_monthly_cents': None,  # contact sales
        'scans_included': None,  # unlimited
        'max_api_keys': 100,
        'overage_rate_cents_per_unit': 0,
        'allow_overage': True,
        'priority_support': True,
    },
}

ANON_DAILY_QUOTA = 10  # scans per IP per day


def get_plan(tier):
    return PLAN_FEATURES.get(tier, PLAN_FEATURES[TIER_FREE])


def get_quota(tier):
    return get_plan(tier)['scans_included']


def allows_overage(tier):
    return get_plan(tier)['allow_overage']


def max_api_keys(tier):
    return get_plan(tier)['max_api_keys']
