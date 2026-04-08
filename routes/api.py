import hashlib
import json
import re
from datetime import datetime, timezone, timedelta

from flask import Blueprint, current_app, jsonify, request

from analysis.classifier import classify_address
from analysis.models import AddressType
from analysis.orchestrator import run_scan
from extensions import db, limiter
from models.report import ScamReport
from models.scan import Scan

api_bp = Blueprint('api', __name__)

VALID_CATEGORIES = {
    'phishing', 'spam', 'fake_account', 'romance_scam',
    'financial_scam', 'malware', 'smishing', 'vishing',
    'investment_fraud', 'tech_support', 'impersonation', 'other',
}


def _hash_ip(ip: str) -> str:
    """Hash IP address for storage (privacy)."""
    salt = current_app.config.get('SECRET_KEY', '')[:16]
    return hashlib.sha256(f'{salt}{ip}'.encode()).hexdigest()[:32]


def _sanitize_text(text: str, max_length: int = 2000) -> str:
    """Strip control characters and limit length."""
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text[:max_length].strip()


@api_bp.route('/scan', methods=['POST'])
@limiter.limit('30/minute;500/day')
def scan():
    data = request.get_json(silent=True)
    if not data or not data.get('address'):
        return jsonify({'error': 'Missing required field: address'}), 400

    raw_address = str(data['address']).strip()
    if len(raw_address) > 500:
        return jsonify({'error': 'Address too long (max 500 chars)'}), 400

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

    response = result.to_dict()
    response['scan_token'] = scan_record.token
    response['checked_at'] = datetime.now(timezone.utc).isoformat()

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

    # Classify and normalize
    address_type, normalized = classify_address(raw_address)

    # Fingerprint for dedup
    ip = request.remote_addr or ''
    ua = request.headers.get('User-Agent', '')
    fingerprint = hashlib.sha256(f'{ip}{ua}'.encode()).hexdigest()

    # Dedup: reject if same fingerprint already reported this address
    existing = ScamReport.query.filter_by(
        reporter_fingerprint=fingerprint,
        address_normalized=normalized,
    ).first()
    if existing:
        return jsonify({'error': 'You have already reported this address'}), 409

    # Flood protection: cap reports per address per day
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
