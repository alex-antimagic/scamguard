import re

import requests

from analysis.models import Finding, Severity


def analyze_instagram(handle: str) -> tuple[list[Finding], dict]:
    """Run Instagram handle analysis. Returns (findings, metadata)."""
    findings = []
    metadata = {'handle': handle}

    # Format validation
    if not re.match(r'^[a-zA-Z0-9_.]{1,30}$', handle):
        findings.append(Finding(
            analyzer='instagram', check='invalid_handle',
            severity=Severity.HIGH,
            detail=f'Invalid Instagram handle format: {handle}',
        ))
        return findings, metadata

    # Profile existence check
    try:
        resp = requests.get(
            f'https://www.instagram.com/{handle}/',
            headers={'User-Agent': 'Mozilla/5.0 (compatible; ScamGuard/1.0)'},
            timeout=5,
            allow_redirects=True,
        )
        if resp.status_code == 404:
            findings.append(Finding(
                analyzer='instagram', check='profile_not_found',
                severity=Severity.MEDIUM,
                detail='Instagram profile does not exist — suspicious if someone directed you here',
            ))
            metadata['profile_exists'] = False
        else:
            metadata['profile_exists'] = True
    except Exception:
        metadata['profile_exists'] = None

    return findings, metadata
