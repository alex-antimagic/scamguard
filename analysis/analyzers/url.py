import math
import re
from urllib.parse import urlparse, unquote

import tldextract
import requests

from analysis.models import Finding, Severity

# Top brands and their legitimate domains
BRANDS = {
    'paypal': ['paypal.com'],
    'apple': ['apple.com', 'icloud.com'],
    'google': ['google.com', 'gmail.com', 'googleapis.com', 'youtube.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'aws.amazon.com'],
    'facebook': ['facebook.com', 'fb.com', 'meta.com'],
    'netflix': ['netflix.com'],
    'instagram': ['instagram.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'whatsapp': ['whatsapp.com'],
    'chase': ['chase.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'wellsfargo': ['wellsfargo.com'],
    'usbank': ['usbank.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'capitalone': ['capitalone.com'],
    'venmo': ['venmo.com'],
    'cashapp': ['cash.app'],
    'zelle': ['zellepay.com'],
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'spotify': ['spotify.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    'bestbuy': ['bestbuy.com'],
    'ebay': ['ebay.com'],
    'dhl': ['dhl.com'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'usps': ['usps.com'],
    'irs': ['irs.gov'],
    'att': ['att.com'],
    'verizon': ['verizon.com'],
    'tmobile': ['t-mobile.com'],
    'comcast': ['comcast.com', 'xfinity.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'epic': ['epicgames.com'],
    'roblox': ['roblox.com'],
    'discord': ['discord.com', 'discord.gg'],
    'telegram': ['telegram.org', 't.me'],
    'zoom': ['zoom.us'],
    'docusign': ['docusign.com', 'docusign.net'],
    'stripe': ['stripe.com'],
    'shopify': ['shopify.com'],
    'squarespace': ['squarespace.com'],
}

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club',
    'work', 'loan', 'click', 'link', 'info', 'wang', 'win', 'bid',
    'stream', 'download', 'racing', 'date', 'faith', 'review',
    'accountant', 'cricket', 'science', 'party',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
    'rb.gy', 'bl.ink', 'short.io', 'qr.ae',
}

SUSPICIOUS_PATH_KEYWORDS = {
    'login', 'signin', 'sign-in', 'verify', 'account', 'secure',
    'update', 'confirm', 'banking', 'password', 'credential',
    'suspend', 'locked', 'unusual', 'verify-identity', 'webscr',
}


def analyze_url(url: str) -> tuple[list[Finding], dict]:
    """Run all URL heuristic checks. Returns (findings, metadata)."""
    findings = []
    metadata = {}

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    metadata['domain'] = ext.registered_domain
    metadata['tld'] = ext.suffix
    metadata['subdomain'] = ext.subdomain

    # --- Critical checks ---

    # Non-HTTP scheme (javascript:, data:, etc.)
    if parsed.scheme and parsed.scheme.lower() not in ('http', 'https', ''):
        findings.append(Finding(
            analyzer='url', check='dangerous_scheme',
            severity=Severity.CRITICAL,
            detail=f'Non-HTTP scheme detected: {parsed.scheme}://',
        ))

    # Homograph / punycode detection
    if ext.domain and ('xn--' in ext.domain.lower() or ext.domain != ext.domain.encode('ascii', 'ignore').decode()):
        findings.append(Finding(
            analyzer='url', check='homograph_detected',
            severity=Severity.CRITICAL,
            detail='Domain uses internationalized characters (punycode) — possible homograph attack',
        ))

    # --- High checks ---

    # IP-based URL
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(parsed.hostname or ''):
        findings.append(Finding(
            analyzer='url', check='ip_based_url',
            severity=Severity.HIGH,
            detail=f'URL uses IP address instead of domain: {parsed.hostname}',
        ))

    # Brand impersonation
    domain_lower = (ext.domain or '').lower()
    registered_domain = (ext.registered_domain or '').lower()
    for brand, legit_domains in BRANDS.items():
        if brand in domain_lower and registered_domain not in legit_domains:
            findings.append(Finding(
                analyzer='url', check='brand_impersonation',
                severity=Severity.HIGH,
                detail=f'Domain contains "{brand}" but is not an official {brand} domain',
            ))
            break

    # At-sign in URL (obfuscation trick)
    if '@' in (parsed.netloc or ''):
        findings.append(Finding(
            analyzer='url', check='at_sign_in_url',
            severity=Severity.HIGH,
            detail='URL contains @ symbol before hostname — possible URL obfuscation',
        ))

    # --- Medium checks ---

    # Suspicious TLD
    if ext.suffix and ext.suffix.lower() in SUSPICIOUS_TLDS:
        findings.append(Finding(
            analyzer='url', check='suspicious_tld',
            severity=Severity.MEDIUM,
            detail=f'Uses suspicious TLD: .{ext.suffix}',
        ))

    # Excessive subdomains (more than 3 levels)
    if ext.subdomain and ext.subdomain.count('.') >= 3:
        findings.append(Finding(
            analyzer='url', check='excessive_subdomains',
            severity=Severity.MEDIUM,
            detail=f'Excessive subdomain depth: {ext.subdomain}',
        ))

    # URL entropy (phishing URLs tend to look random)
    entropy = _shannon_entropy(url)
    if entropy > 4.5:
        findings.append(Finding(
            analyzer='url', check='high_entropy',
            severity=Severity.MEDIUM,
            detail=f'URL has high randomness (entropy: {entropy:.1f}) — common in phishing URLs',
        ))

    # Suspicious keywords in path
    path_lower = (parsed.path or '').lower() + (parsed.query or '').lower()
    found_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_lower]
    if found_keywords:
        findings.append(Finding(
            analyzer='url', check='suspicious_path_keywords',
            severity=Severity.MEDIUM,
            detail=f'Path contains suspicious keywords: {", ".join(found_keywords)}',
        ))

    # Double encoding
    if '%25' in url:
        findings.append(Finding(
            analyzer='url', check='double_encoding',
            severity=Severity.MEDIUM,
            detail='URL contains double-encoded characters (%25) — possible obfuscation',
        ))

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443, None):
        findings.append(Finding(
            analyzer='url', check='non_standard_port',
            severity=Severity.MEDIUM,
            detail=f'Non-standard port: {parsed.port}',
        ))

    # --- Low checks ---

    # URL shortener
    if registered_domain in URL_SHORTENERS:
        findings.append(Finding(
            analyzer='url', check='url_shortener',
            severity=Severity.LOW,
            detail=f'URL shortener detected ({registered_domain}) — destination is opaque',
        ))

    # Excessive path length
    if len(parsed.path or '') > 200:
        findings.append(Finding(
            analyzer='url', check='excessive_path_length',
            severity=Severity.LOW,
            detail=f'Unusually long path ({len(parsed.path)} chars)',
        ))

    # No HTTPS
    if parsed.scheme == 'http':
        findings.append(Finding(
            analyzer='url', check='no_https',
            severity=Severity.LOW,
            detail='Site uses HTTP instead of HTTPS',
        ))

    return findings, metadata


def check_safe_browsing(url: str, api_key: str) -> list[Finding]:
    """Check URL against Google Safe Browsing API v4."""
    if not api_key:
        return []

    try:
        resp = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
            json={
                'client': {'clientId': 'scamguard', 'clientVersion': '1.0'},
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION',
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}],
                },
            },
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get('matches'):
            threats = [m['threatType'] for m in data['matches']]
            return [Finding(
                analyzer='blocklist', check='google_safe_browsing',
                severity=Severity.CRITICAL,
                detail=f'Flagged by Google Safe Browsing: {", ".join(threats)}',
            )]
    except Exception:
        pass

    return []


def check_whois_age(domain: str) -> list[Finding]:
    """Check domain age via WHOIS. Returns findings if domain is young."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            from datetime import datetime, timezone
            age_days = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            if age_days < 30:
                return [Finding(
                    analyzer='whois', check='domain_very_new',
                    severity=Severity.HIGH,
                    detail=f'Domain registered only {age_days} days ago',
                )]
            elif age_days < 90:
                return [Finding(
                    analyzer='whois', check='domain_new',
                    severity=Severity.MEDIUM,
                    detail=f'Domain registered {age_days} days ago',
                )]
    except Exception:
        pass
    return []


def check_dns(domain: str) -> list[Finding]:
    """Check DNS resolution for suspicious patterns."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            # Check for private IPs
            if (ip.startswith('10.') or ip.startswith('192.168.') or
                    ip.startswith('127.') or
                    (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
                return [Finding(
                    analyzer='dns', check='private_ip',
                    severity=Severity.HIGH,
                    detail=f'Domain resolves to private IP: {ip}',
                )]
    except Exception:
        return [Finding(
            analyzer='dns', check='no_dns_record',
            severity=Severity.INFO,
            detail='Domain does not resolve (no DNS A record)',
        )]
    return []


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())
