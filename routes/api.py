import hashlib
import json
import re
from datetime import datetime, timezone, timedelta

from flask import Blueprint, current_app, jsonify, request, g
from flask_login import current_user

from analysis.classifier import classify_address
from analysis.models import AddressType
from analysis.orchestrator import run_scan
from extensions import db, limiter
from models.api_key import ApiKey, KEY_PREFIX
from models.report import ScamReport
from models.scan import Scan
from services.usage_service import build_caller_from_request, check_quota, record_usage

api_bp = Blueprint('api', __name__)

VALID_CATEGORIES = {
    'phishing', 'spam', 'fake_account', 'romance_scam',
    'financial_scam', 'malware', 'smishing', 'vishing',
    'investment_fraud', 'tech_support', 'impersonation', 'other',
}


def _hash_ip(ip: str) -> str:
    salt = current_app.config.get('SECRET_KEY', '')[:16]
    return hashlib.sha256(f'{salt}{ip}'.encode()).hexdigest()[:32]


def _sanitize_text(text: str, max_length: int = 2000) -> str:
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text[:max_length].strip()


def _authenticate_request():
    """Identify the caller. Sets g.user and g.api_key if authenticated via API key.

    Precedence:
    1. Authorization: Bearer sg_live_... → API key → user
    2. Flask-Login session (portal user)
    3. Anonymous

    Sets g.user / g.api_key (both may be None).
    """
    g.user = None
    g.api_key = None

    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        candidate = auth_header[len('Bearer '):].strip()
        if candidate.startswith(KEY_PREFIX):
            prefix = candidate[:16]
            # Narrow by prefix, then bcrypt.checkpw for each (usually 1 match)
            possible = ApiKey.query.filter_by(key_prefix=prefix, is_active=True).all()
            for key in possible:
                if key.verify(candidate) and key.user and key.user.is_active:
                    g.user = key.user
                    g.api_key = key
                    return
        return  # bad key → treat as anonymous (will still be quota-limited)

    # Session auth (portal user)
    if current_user.is_authenticated and current_user.is_active:
        g.user = current_user


@api_bp.before_request
def _before_request():
    _authenticate_request()


def _quota_error_response(result):
    messages = {
        'anon_cap': 'Daily anonymous quota reached. Create a free account for 100 scans/month.',
        'free_cap': 'Your monthly scan quota is used up. Upgrade to continue.',
        'no_subscription': 'Account has no active subscription.',
    }
    msg = messages.get(result.reason, 'Rate limit exceeded')
    return jsonify({
        'error': msg,
        'reason': result.reason,
        'limit': result.limit,
        'remaining': 0,
        'upgrade_url': '/app/billing',
    }), 429


@api_bp.route('/scan', methods=['POST'])
@limiter.limit('60/minute', key_func=lambda: f'api_key:{g.api_key.id}' if getattr(g, 'api_key', None) else request.remote_addr)
def scan():
    data = request.get_json(silent=True)
    if not data or not data.get('address'):
        return jsonify({'error': 'Missing required field: address'}), 400

    raw_address = str(data['address']).strip()
    if len(raw_address) > 500:
        return jsonify({'error': 'Address too long (max 500 chars)'}), 400

    # Build caller + check quota BEFORE running the scan
    caller = build_caller_from_request(request, g_user=g.user, g_api_key=g.api_key)
    quota = check_quota(caller)
    if not quota.allowed:
        return _quota_error_response(quota)

    # Run the scan
    result = run_scan(raw_address)

    # Persist scan
    scan_record = Scan(
        address_type=result.address_type.value,
        address_raw=result.address_raw,
        address_normalized=result.address_normalized,
        risk_score=result.risk_score,
        verdict=result.verdict,
        findings_json=json.dumps([f.to_dict() for f in result.findings]),
        metadata_json=json.dumps(result.metadata),
        requester_ip=_hash_ip(request.remote_addr or ''),
        analysis_time_ms=result.analysis_time_ms,
    )
    db.session.add(scan_record)
    db.session.commit()

    # Record usage
    record_usage(caller,
                 scan_id=scan_record.id,
                 address_type=result.address_type.value)

    response = result.to_dict()
    response['scan_token'] = scan_record.token
    response['checked_at'] = datetime.now(timezone.utc).isoformat()
    response['quota'] = {
        'limit': quota.limit,
        'remaining': (quota.remaining - 1) if quota.remaining is not None else None,
        'reason': quota.reason,
    }

    return jsonify(response)


@api_bp.route('/scan/<token>', methods=['GET'])
@limiter.limit('60/minute')
def get_scan(token):
    scan_record = Scan.query.filter_by(token=token).first()
    if not scan_record:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify({
        'scan_token': scan_record.token,
        'address': {
            'raw': scan_record.address_raw,
            'normalized': scan_record.address_normalized,
            'type': scan_record.address_type,
        },
        'risk_score': scan_record.risk_score,
        'verdict': scan_record.verdict,
        'findings': json.loads(scan_record.findings_json or '[]'),
        'metadata': json.loads(scan_record.metadata_json or '{}'),
        'analysis_time_ms': scan_record.analysis_time_ms,
        'checked_at': scan_record.created_at.isoformat(),
    })


@api_bp.route('/report', methods=['POST'])
@limiter.limit('10/hour')
def report():
    data = request.get_json(silent=True)
    if not data or not data.get('address'):
        return jsonify({'error': 'Missing required field: address'}), 400

    raw_address = str(data['address']).strip()
    category = data.get('category', 'other')
    description = data.get('description', '')

    if category not in VALID_CATEGORIES:
        return jsonify({'error': f'Invalid category. Must be one of: {", ".join(sorted(VALID_CATEGORIES))}'}), 400

    if len(raw_address) > 500:
        return jsonify({'error': 'Address too long (max 500 chars)'}), 400

    address_type, normalized = classify_address(raw_address)

    ip = request.remote_addr or ''
    ua = request.headers.get('User-Agent', '')
    fingerprint = hashlib.sha256(f'{ip}{ua}'.encode()).hexdigest()

    existing = ScamReport.query.filter_by(
        reporter_fingerprint=fingerprint,
        address_normalized=normalized,
    ).first()
    if existing:
        return jsonify({'error': 'You have already reported this address'}), 409

    today_start = datetime.now(timezone.utc) - timedelta(hours=24)
    daily_count = ScamReport.query.filter(
        ScamReport.address_normalized == normalized,
        ScamReport.created_at >= today_start,
    ).count()
    if daily_count >= 50:
        return jsonify({'error': 'Maximum daily reports reached for this address'}), 429

    report_record = ScamReport(
        address_type=address_type.value,
        address_raw=raw_address,
        address_normalized=normalized,
        reporter_ip=_hash_ip(ip),
        reporter_fingerprint=fingerprint,
        category=category,
        description=_sanitize_text(description) if description else None,
    )
    db.session.add(report_record)
    db.session.commit()

    return jsonify({
        'report_token': report_record.token,
        'status': 'received',
    }), 201
