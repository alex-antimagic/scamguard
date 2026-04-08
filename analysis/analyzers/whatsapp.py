import phonenumbers

from analysis.models import Finding, Severity


def analyze_whatsapp(normalized: str) -> tuple[list[Finding], dict]:
    """Run WhatsApp number analysis. Returns (findings, metadata)."""
    findings = []
    metadata = {}

    try:
        parsed = phonenumbers.parse(normalized, None)
    except phonenumbers.NumberParseException:
        findings.append(Finding(
            analyzer='whatsapp', check='invalid_number',
            severity=Severity.HIGH,
            detail='Could not parse WhatsApp number — may be invalid',
        ))
        return findings, metadata

    country_code = phonenumbers.region_code_for_number(parsed)
    metadata['country'] = country_code or 'Unknown'

    carrier_name = phonenumbers.carrier.name_for_number(parsed, 'en')
    metadata['carrier'] = carrier_name or 'Unknown'

    if not phonenumbers.is_valid_number(parsed):
        findings.append(Finding(
            analyzer='whatsapp', check='invalid_format',
            severity=Severity.MEDIUM,
            detail='Number format is invalid for its region',
        ))

    return findings, metadata
