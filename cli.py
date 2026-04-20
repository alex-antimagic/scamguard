"""Flask CLI commands for operational tasks."""
import click
from flask.cli import with_appcontext

from extensions import db
from services.billing_service import _get_stripe
from services.plan_gating import PLAN_FEATURES


def register_commands(app):
    app.cli.add_command(stripe_init_products)
    app.cli.add_command(report_overage)


@click.command('stripe-init-products')
@with_appcontext
def stripe_init_products():
    """Create Stripe Products and Prices for Starter and Pro tiers.

    Prints the price IDs to set in Heroku config.
    Idempotent by product name lookup — re-running is safe.
    """
    stripe = _get_stripe()
    if not stripe:
        click.echo('STRIPE_SECRET_KEY is not set. Aborting.')
        return

    for tier in ('starter', 'pro'):
        plan = PLAN_FEATURES[tier]
        name = f"ScamGuard {plan['display_name']}"
        # Look up existing product
        existing = stripe.Product.search(query=f'name:"{name}"').data
        if existing:
            product = existing[0]
            click.echo(f'Found existing product: {product.id} ({name})')
        else:
            product = stripe.Product.create(
                name=name,
                description=f"{plan['scans_included']:,} scans/month, {plan['max_api_keys']} API keys",
                metadata={'tier': tier},
            )
            click.echo(f'Created product: {product.id} ({name})')

        # Look up existing monthly recurring price
        prices = stripe.Price.list(product=product.id, active=True, limit=100).data
        price = None
        for p in prices:
            if (p.recurring and p.recurring.get('interval') == 'month'
                    and p.unit_amount == plan['price_monthly_cents']
                    and not p.recurring.get('usage_type') == 'metered'):
                price = p
                break

        if price:
            click.echo(f'  Found existing monthly price: {price.id}')
        else:
            price = stripe.Price.create(
                product=product.id,
                unit_amount=plan['price_monthly_cents'],
                currency='usd',
                recurring={'interval': 'month'},
                metadata={'tier': tier},
            )
            click.echo(f'  Created monthly price: {price.id}')

        click.echo(f'  ➜ Set STRIPE_{tier.upper()}_PRICE_ID={price.id}')
        click.echo('')

    click.echo('Done. Update your Heroku config vars with the IDs above.')


@click.command('report-overage')
@with_appcontext
def report_overage():
    """Placeholder for metered overage reporting.

    To be implemented when a metered Stripe price is added.
    For MVP, Starter and Pro tiers are fixed monthly with quota displayed in UI.
    """
    click.echo('Overage reporting not yet implemented (fixed-price tiers for MVP).')
