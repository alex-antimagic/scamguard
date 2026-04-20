from __future__ import annotations

import re
from urllib.parse import urlparse

import phonenumbers
import tldextract

from analysis.models import AddressType


def classify_address(raw: str) -> tuple[AddressType, str]:
    """Classify raw input and return (address_type, normalized_value)."""
    raw = raw.strip()
    if not raw:
        return AddressType.UNKNOWN, raw

    # 1. Explicit URL schemes
    if re.match(r'^https?://', raw, re.IGNORECASE):
        return AddressType.URL, raw

    # 2. Instagram URL
    if 'instagram.com/' in raw.lower():
        handle = _extract_instagram_handle(raw)
        if handle:
            return AddressType.INSTAGRAM, handle

    # 3. Instagram handle (@username)
    if raw.startswith('@') and re.match(r'^@[a-zA-Z0-9_.]{1,30}$', raw):
        return AddressType.INSTAGRAM, raw[1:].lower()

    # 4. WhatsApp link
    if 'wa.me/' in raw.lower():
        number = _extract_wa_number(raw)
        if number:
            return AddressType.WHATSAPP, number

    # 5. Phone number (try parsing with phonenumbers)
    phone = _try_parse_phone(raw)
    if phone:
        return AddressType.PHONE, phone

    # 6. Bare domain (contains dot with valid TLD, no spaces)
    if ' ' not in raw and '.' in raw:
        ext = tldextract.extract(raw)
        if ext.domain and ext.suffix:
            return AddressType.URL, f'https://{raw}'

    return AddressType.UNKNOWN, raw


def _extract_instagram_handle(raw: str) -> str | None:
    match = re.search(r'instagram\.com/([a-zA-Z0-9_.]{1,30})', raw, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _extract_wa_number(raw: str) -> str | None:
    """Extract and E.164-normalize a WhatsApp number from a wa.me link."""
    match = re.search(r'wa\.me/(\+?\d{7,15})', raw, re.IGNORECASE)
    if not match:
        return None
    num = match.group(1)
    if not num.startswith('+'):
        num = '+' + num
    try:
        parsed = phonenumbers.parse(num, None)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
    except phonenumbers.NumberParseException:
        pass
    return None


def _try_parse_phone(raw: str) -> str | None:
    """Try to parse as phone number. Returns E.164 format or None."""
    # Strip common non-phone chars but keep +, digits, spaces, parens, dashes
    cleaned = re.sub(r'[^\d+() \-]', '', raw)
    if not cleaned:
        return None

    # Need at least 7 digits
    digits_only = re.sub(r'\D', '', cleaned)
    if len(digits_only) < 7 or len(digits_only) > 15:
        return None

    try:
        # Try with + prefix first
        if cleaned.startswith('+'):
            parsed = phonenumbers.parse(cleaned, None)
        else:
            # Default to US if no country code
            parsed = phonenumbers.parse(cleaned, 'US')

        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
    except phonenumbers.NumberParseException:
        pass

    return None
