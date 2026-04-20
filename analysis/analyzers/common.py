import requests

from analysis.models import Finding, Severity, AddressType


def check_internal_reports(address_normalized: str, db_session,
                           address_type=None) -> list[Finding]:
    """Check how many times this address (or its domain, for URLs) has been reported."""
    from models.report import ScamReport
    from analysis.models import AddressType

    # Exact match first
    count = db_session.query(ScamReport).filter(
        ScamReport.address_normalized == address_normalized,
        ScamReport.status != 'rejected',
    ).count()

    detail_suffix = ''

    # For URLs, also match on domain — so scanning a bare domain matches reports
    # of specific URLs on that domain (and vice versa).
    if address_type == AddressType.URL and count == 0:
        try:
            import tldextract
            ext = tldextract.extract(address_normalized)
            domain = ext.registered_domain
            if domain:
                domain_count = db_session.query(ScamReport).filter(
                    ScamReport.address_type == 'url',
                    ScamReport.address_normalized.like(f'%{domain}%'),
                    ScamReport.status != 'rejected',
                ).count()
                if domain_count > 0:
                    count = domain_count
                    detail_suffix = f' on domain {domain}'
        except Exception:
            pass

    if count == 0:
        return []

    if count >= 10:
        severity = Severity.HIGH
    elif count >= 3:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    return [Finding(
        analyzer='reports', check='user_reports',
        severity=severity,
        detail=f'Reported {count} time{"s" if count != 1 else ""} by users as suspicious{detail_suffix}',
    )]


def check_google_search(address: str, address_type: AddressType,
                         api_key: str, engine_id: str) -> list[Finding]:
    """Search Google for scam reports about this address."""
    if not api_key or not engine_id:
        return []

    # Build query based on type
    query_map = {
        AddressType.URL: f'"{address}" scam OR phishing OR fraud',
        AddressType.PHONE: f'"{address}" scam OR spam OR fraud',
        AddressType.WHATSAPP: f'"{address}" whatsapp scam OR fraud',
        AddressType.INSTAGRAM: f'"{address}" instagram scam OR fraud OR fake',
    }
    query = query_map.get(address_type, f'"{address}" scam OR fraud')

    try:
        resp = requests.get(
            'https://www.googleapis.com/customsearch/v1',
            params={
                'key': api_key,
                'cx': engine_id,
                'q': query,
                'num': 5,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        total = int(data.get('searchInformation', {}).get('totalResults', 0))

        if total == 0:
            return []

        if total > 20:
            severity = Severity.HIGH
        elif total > 5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return [Finding(
            analyzer='search', check='google_scam_reports',
            severity=severity,
            detail=f'Found {total} scam/fraud report{"s" if total != 1 else ""} online for this address',
        )]
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning('Google CSE check failed: %s', e)
        return []
