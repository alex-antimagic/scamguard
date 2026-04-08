import time

from flask import current_app

from analysis.models import AddressType, AnalysisResult
from analysis.classifier import classify_address
from analysis.scorer import compute_score
from analysis.analyzers.url import analyze_url, check_safe_browsing, check_whois_age, check_dns
from analysis.analyzers.phone import analyze_phone
from analysis.analyzers.instagram import analyze_instagram
from analysis.analyzers.whatsapp import analyze_whatsapp
from analysis.analyzers.common import check_internal_reports, check_google_search
from extensions import db


def run_scan(raw_address: str) -> AnalysisResult:
    """Run full analysis pipeline on a raw address input."""
    start = time.time()

    address_type, normalized = classify_address(raw_address)

    result = AnalysisResult(
        address_raw=raw_address,
        address_normalized=normalized,
        address_type=address_type,
    )

    if address_type == AddressType.UNKNOWN:
        result.findings = []
        result.risk_score = 0
        result.verdict = 'unknown'
        result.metadata = {'note': 'Could not determine address type'}
        result.analysis_time_ms = int((time.time() - start) * 1000)
        return result

    # Phase 1: Type-specific analyzers
    findings = []
    metadata = {}

    if address_type == AddressType.URL:
        f, m = analyze_url(normalized)
        findings.extend(f)
        metadata.update(m)

        # Safe Browsing check
        api_key = current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
        findings.extend(check_safe_browsing(normalized, api_key))

    elif address_type == AddressType.PHONE:
        f, m = analyze_phone(normalized)
        findings.extend(f)
        metadata.update(m)

    elif address_type == AddressType.INSTAGRAM:
        f, m = analyze_instagram(normalized)
        findings.extend(f)
        metadata.update(m)

    elif address_type == AddressType.WHATSAPP:
        f, m = analyze_whatsapp(normalized)
        findings.extend(f)
        metadata.update(m)

    # Phase 2: Shared analyzers
    # Internal reports DB
    findings.extend(check_internal_reports(normalized, db.session))

    # Google Custom Search
    cse_key = current_app.config.get('GOOGLE_CSE_API_KEY', '')
    cse_id = current_app.config.get('GOOGLE_CSE_ENGINE_ID', '')
    findings.extend(check_google_search(normalized, address_type, cse_key, cse_id))

    # Phase 3: Conditional deep checks (URL only, if score is ambiguous)
    if address_type == AddressType.URL:
        preliminary_score, _ = compute_score(findings)
        if 20 <= preliminary_score <= 70:
            domain = metadata.get('domain', '')
            if domain:
                findings.extend(check_whois_age(domain))
                findings.extend(check_dns(domain))

    # Final scoring
    score, verdict = compute_score(findings)

    result.findings = findings
    result.risk_score = score
    result.verdict = verdict
    result.metadata = metadata
    result.analysis_time_ms = int((time.time() - start) * 1000)

    return result
