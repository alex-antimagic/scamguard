import phonenumbers
from phonenumbers import carrier, number_type

from analysis.models import Finding, Severity


def analyze_phone(normalized: str) -> tuple[list[Finding], dict]:
    """Run phone number analysis. Returns (findings, metadata)."""
    findings = []
    metadata = {}

    try:
        parsed = phonenumbers.parse(normalized, None)
    except phonenumbers.NumberParseException:
        findings.append(Finding(
            analyzer='phone', check='invalid_number',
            severity=Severity.HIGH,
            detail='Could not parse phone number — may be invalid',
        ))
        return findings, metadata

    # Basic info
    country_code = phonenumbers.region_code_for_number(parsed)
    metadata['country'] = country_code or 'Unknown'

    # Carrier info
    carrier_name = carrier.name_for_number(parsed, 'en')
    metadata['carrier'] = carrier_name or 'Unknown'

    # Line type
    ntype = number_type(parsed)
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: 'mobile',
        phonenumbers.PhoneNumberType.FIXED_LINE: 'landline',
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'fixed_or_mobile',
        phonenumbers.PhoneNumberType.VOIP: 'voip',
        phonenumbers.PhoneNumberType.TOLL_FREE: 'toll_free',
        phonenumbers.PhoneNumberType.PREMIUM_RATE: 'premium_rate',
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'personal',
    }
    line_type = type_map.get(ntype, 'unknown')
    metadata['line_type'] = line_type

    # VOIP detection — higher scam risk
    if ntype == phonenumbers.PhoneNumberType.VOIP:
        findings.append(Finding(
            analyzer='phone', check='voip_number',
            severity=Severity.MEDIUM,
            detail='VOIP number detected — commonly used for scam calls',
        ))

    # Premium rate number
    if ntype == phonenumbers.PhoneNumberType.PREMIUM_RATE:
        findings.append(Finding(
            analyzer='phone', check='premium_rate',
            severity=Severity.HIGH,
            detail='Premium-rate number — calling may incur high charges',
        ))

    # Toll-free (often used by legit businesses but also scammers)
    if ntype == phonenumbers.PhoneNumberType.TOLL_FREE:
        findings.append(Finding(
            analyzer='phone', check='toll_free',
            severity=Severity.INFO,
            detail='Toll-free number',
        ))

    # Validity check
    if not phonenumbers.is_valid_number(parsed):
        findings.append(Finding(
            analyzer='phone', check='invalid_format',
            severity=Severity.MEDIUM,
            detail='Phone number format is invalid for its region',
        ))

    return findings, metadata
