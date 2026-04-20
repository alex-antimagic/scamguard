from datetime import datetime, timezone, timedelta

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, jsonify)
from flask_login import login_required, current_user
from sqlalchemy import func

from extensions import db
from models.api_key import ApiKey
from models.scan import Scan
from models.usage_event import UsageEvent
from services.plan_gating import get_plan, max_api_keys

app_bp = Blueprint('app', __name__, url_prefix='/app',
                   template_folder='../templates')


def _period_start(sub):
    """Start of current billing period (or month-to-date for free tier)."""
    if sub and sub.current_period_start:
        return sub.current_period_start
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


@app_bp.route('/scan')
@login_required
def scan():
    return render_template('app/scan.html')


@app_bp.route('/')
@login_required
def overview():
    sub = current_user.subscription
    plan = get_plan(sub.plan_tier)
    period_start = _period_start(sub)

    scans_this_period = UsageEvent.query.filter(
        UsageEvent.user_id == current_user.id,
        UsageEvent.created_at >= period_start,
    ).count()

    by_source = db.session.query(
        UsageEvent.source, func.count(UsageEvent.id)
    ).filter(
        UsageEvent.user_id == current_user.id,
        UsageEvent.created_at >= period_start,
    ).group_by(UsageEvent.source).all()
    source_counts = {s: c for s, c in by_source}

    by_verdict = db.session.query(
        Scan.verdict, func.count(Scan.id)
    ).join(UsageEvent, UsageEvent.scan_id == Scan.id).filter(
        UsageEvent.user_id == current_user.id,
        UsageEvent.created_at >= period_start,
    ).group_by(Scan.verdict).all()
    verdict_counts = {v: c for v, c in by_verdict}

    recent_events = UsageEvent.query.filter_by(user_id=current_user.id) \
        .order_by(UsageEvent.created_at.desc()).limit(10).all()
    recent_scan_ids = [e.scan_id for e in recent_events if e.scan_id]
    recent_scans_map = {s.id: s for s in Scan.query.filter(Scan.id.in_(recent_scan_ids)).all()} if recent_scan_ids else {}
    recent = []
    for e in recent_events:
        if e.scan_id and e.scan_id in recent_scans_map:
            recent.append({
                'created_at': e.created_at,
                'source': e.source,
                'scan': recent_scans_map[e.scan_id],
            })

    return render_template('app/overview.html',
                           plan=plan,
                           scans_this_period=scans_this_period,
                           quota=sub.scans_included,
                           source_counts=source_counts,
                           verdict_counts=verdict_counts,
                           recent=recent,
                           subscription=sub)


@app_bp.route('/history')
@login_required
def history():
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50

    # Join usage_events → scans so we only show the user's scans
    query = db.session.query(Scan, UsageEvent) \
        .join(UsageEvent, UsageEvent.scan_id == Scan.id) \
        .filter(UsageEvent.user_id == current_user.id) \
        .order_by(UsageEvent.created_at.desc())

    total = query.count()
    rows = query.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template('app/history.html',
                           rows=rows, page=page, total=total,
                           total_pages=total_pages)


@app_bp.route('/api-keys')
@login_required
def api_keys():
    keys = current_user.api_keys.order_by(ApiKey.created_at.desc()).all()
    plan = get_plan(current_user.subscription.plan_tier)
    active_count = sum(1 for k in keys if k.is_active)
    return render_template('app/api_keys.html',
                           keys=keys,
                           plan=plan,
                           active_count=active_count,
                           max_keys=max_api_keys(current_user.subscription.plan_tier))


@app_bp.route('/api-keys/create', methods=['POST'])
@login_required
def create_api_key():
    if not current_user.is_email_verified:
        flash('Please verify your email before creating API keys.', 'error')
        return redirect(url_for('app.api_keys'))

    name = request.form.get('name', '').strip() or 'New key'
    active_count = current_user.api_keys.filter_by(is_active=True).count()
    limit = max_api_keys(current_user.subscription.plan_tier)
    if active_count >= limit:
        flash(f'Your {current_user.subscription.plan_tier} plan is limited to {limit} active API keys.', 'error')
        return redirect(url_for('app.api_keys'))

    api_key, plaintext = ApiKey.generate(current_user, name)
    db.session.add(api_key)
    db.session.commit()

    return render_template('app/api_keys.html',
                           keys=current_user.api_keys.order_by(ApiKey.created_at.desc()).all(),
                           plan=get_plan(current_user.subscription.plan_tier),
                           active_count=active_count + 1,
                           max_keys=limit,
                           new_key_plaintext=plaintext,
                           new_key_name=name)


@app_bp.route('/api-keys/<token>/revoke', methods=['POST'])
@login_required
def revoke_api_key(token):
    key = current_user.api_keys.filter_by(token=token).first()
    if not key:
        flash('API key not found.', 'error')
        return redirect(url_for('app.api_keys'))
    key.revoke()
    db.session.commit()
    flash(f'Key "{key.name}" revoked.', 'success')
    return redirect(url_for('app.api_keys'))


@app_bp.route('/billing')
@login_required
def billing():
    sub = current_user.subscription
    plan = get_plan(sub.plan_tier)
    period_start = _period_start(sub)
    scans_this_period = UsageEvent.query.filter(
        UsageEvent.user_id == current_user.id,
        UsageEvent.created_at >= period_start,
    ).count()

    overage = max(0, scans_this_period - (sub.scans_included or 0))
    overage_cost_cents = int(overage * (sub.overage_rate_cents or 0))

    return render_template('app/billing.html',
                           plan=plan,
                           subscription=sub,
                           scans_this_period=scans_this_period,
                           overage=overage,
                           overage_cost_cents=overage_cost_cents)


@app_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            current_user.name = request.form.get('name', '').strip() or None
            db.session.commit()
            flash('Profile updated.', 'success')

        elif action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            if not current_user.check_password(current_pw):
                flash('Current password is incorrect.', 'error')
            elif len(new_pw) < 8:
                flash('New password must be at least 8 characters.', 'error')
            else:
                current_user.set_password(new_pw)
                db.session.commit()
                flash('Password updated.', 'success')

        return redirect(url_for('app.settings'))

    return render_template('app/settings.html')
