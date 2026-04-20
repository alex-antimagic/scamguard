from flask import Blueprint, request, redirect, url_for, flash, render_template, current_app
from flask_login import login_required, current_user

from services.billing_service import (create_checkout_session, create_portal_session,
                                       stripe_configured)
from services.plan_gating import PLAN_FEATURES
from models.subscription import TIER_STARTER, TIER_PRO

billing_bp = Blueprint('billing', __name__, url_prefix='/app/billing',
                       template_folder='../templates')


@billing_bp.route('/upgrade')
@login_required
def upgrade():
    return render_template('app/billing_upgrade.html',
                           plans=PLAN_FEATURES,
                           current_tier=current_user.subscription.plan_tier,
                           stripe_ready=stripe_configured())


@billing_bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    tier = request.form.get('tier')
    if tier not in (TIER_STARTER, TIER_PRO):
        flash('Invalid plan selection.', 'error')
        return redirect(url_for('billing.upgrade'))

    if not stripe_configured():
        flash('Billing is not available yet. Please check back soon.', 'error')
        return redirect(url_for('billing.upgrade'))

    base = current_app.config.get('APP_BASE_URL', request.host_url.rstrip('/'))
    session = create_checkout_session(
        current_user, tier,
        success_url=f'{base}/app/billing?checkout=success',
        cancel_url=f'{base}/app/billing/upgrade',
    )
    if not session:
        flash('Could not start checkout. Please try again.', 'error')
        return redirect(url_for('billing.upgrade'))

    return redirect(session.url, code=303)


@billing_bp.route('/portal', methods=['POST'])
@login_required
def portal():
    if not current_user.stripe_customer_id:
        flash('No billing account yet. Subscribe to a paid plan first.', 'info')
        return redirect(url_for('app.billing'))

    base = current_app.config.get('APP_BASE_URL', request.host_url.rstrip('/'))
    session = create_portal_session(current_user, return_url=f'{base}/app/billing')
    if not session:
        flash('Could not open billing portal.', 'error')
        return redirect(url_for('app.billing'))

    return redirect(session.url, code=303)
