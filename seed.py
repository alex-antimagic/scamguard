"""Seed the database with test data for development."""
import hashlib
from datetime import datetime, timezone, timedelta

from app import create_app
from extensions import db
from models.report import ScamReport

SEED_REPORTS = [
    # Phone numbers - spam callers
    {
        'address_type': 'phone',
        'address_raw': '+1 (800) 555-0199',
        'address_normalized': '+18005550199',
        'category': 'spam',
        'description': 'Robocall about extended car warranty. Calls 3x daily.',
        'count': 47,
    },
    {
        'address_type': 'phone',
        'address_raw': '+1 (323) 555-0142',
        'address_normalized': '+13235550142',
        'category': 'financial_scam',
        'description': 'Claims to be IRS, demands immediate payment via gift cards.',
        'count': 23,
    },
    {
        'address_type': 'phone',
        'address_raw': '+1 (206) 555-0188',
        'address_normalized': '+12065550188',
        'category': 'spam',
        'description': 'Solar panel sales, very aggressive, won\'t stop calling.',
        'count': 8,
    },
    {
        'address_type': 'phone',
        'address_raw': '+44 7911 123456',
        'address_normalized': '+447911123456',
        'category': 'financial_scam',
        'description': 'WhatsApp message claiming to be from HMRC about tax refund.',
        'count': 15,
    },
    {
        'address_type': 'phone',
        'address_raw': '+1 (415) 555-0177',
        'address_normalized': '+14155550177',
        'category': 'spam',
        'description': 'Fake Amazon delivery notification, asks for credit card.',
        'count': 31,
    },

    # URLs - phishing/scam sites
    {
        'address_type': 'url',
        'address_raw': 'http://paypa1-secure-login.tk/verify',
        'address_normalized': 'http://paypa1-secure-login.tk/verify',
        'category': 'phishing',
        'description': 'Fake PayPal login page. Steals credentials.',
        'count': 52,
    },
    {
        'address_type': 'url',
        'address_raw': 'https://amaz0n-delivery-update.xyz/track',
        'address_normalized': 'https://amaz0n-delivery-update.xyz/track',
        'category': 'phishing',
        'description': 'Fake Amazon delivery tracking page, asks for payment info.',
        'count': 19,
    },
    {
        'address_type': 'url',
        'address_raw': 'https://crypto-doubler-elon.com/invest',
        'address_normalized': 'https://crypto-doubler-elon.com/invest',
        'category': 'financial_scam',
        'description': 'Fake crypto investment scheme promising 10x returns.',
        'count': 34,
    },
    {
        'address_type': 'url',
        'address_raw': 'http://microsoft-alert-security.ml/warning',
        'address_normalized': 'http://microsoft-alert-security.ml/warning',
        'category': 'phishing',
        'description': 'Fake Microsoft security alert, installs malware.',
        'count': 27,
    },

    # Instagram handles - fake accounts
    {
        'address_type': 'instagram',
        'address_raw': '@crypto_millionaire_tips',
        'address_normalized': 'crypto_millionaire_tips',
        'category': 'financial_scam',
        'description': 'Fake crypto guru, DMs people promising guaranteed returns then asks for "investment".',
        'count': 14,
    },
    {
        'address_type': 'instagram',
        'address_raw': '@free.iphone.giveaway.2026',
        'address_normalized': 'free.iphone.giveaway.2026',
        'category': 'fake_account',
        'description': 'Fake giveaway account, harvests personal info.',
        'count': 9,
    },
    {
        'address_type': 'instagram',
        'address_raw': '@sugar_daddy_real_pay',
        'address_normalized': 'sugar_daddy_real_pay',
        'category': 'romance_scam',
        'description': 'Romance/sugar scam, asks for "verification fee" upfront.',
        'count': 21,
    },

    # WhatsApp numbers
    {
        'address_type': 'whatsapp',
        'address_raw': '+234 801 234 5678',
        'address_normalized': '+2348012345678',
        'category': 'financial_scam',
        'description': 'Advance-fee scam. Claims you won a lottery, need to pay processing fee.',
        'count': 38,
    },
    {
        'address_type': 'whatsapp',
        'address_raw': '+91 98765 43210',
        'address_normalized': '+919876543210',
        'category': 'spam',
        'description': 'Bulk WhatsApp spam about forex trading signals group.',
        'count': 11,
    },
]


def seed():
    app = create_app()
    with app.app_context():
        # Check if already seeded
        existing = ScamReport.query.count()
        if existing > 0:
            print(f'Database already has {existing} reports. Clearing and re-seeding...')
            ScamReport.query.delete()
            db.session.commit()

        total = 0
        for entry in SEED_REPORTS:
            for i in range(entry['count']):
                fake_ip = f'198.51.100.{(i * 7 + hash(entry["address_normalized"])) % 256}'
                fingerprint = hashlib.sha256(
                    f'{fake_ip}Mozilla/5.0 seed-{i}'.encode()
                ).hexdigest()

                report = ScamReport(
                    address_type=entry['address_type'],
                    address_raw=entry['address_raw'],
                    address_normalized=entry['address_normalized'],
                    reporter_ip=fake_ip,
                    reporter_fingerprint=fingerprint,
                    category=entry['category'],
                    description=entry['description'] if i == 0 else None,
                    status='pending',
                )
                # Stagger creation dates over the last 90 days
                report.created_at = datetime.now(timezone.utc) - timedelta(
                    days=int(90 * (i / max(entry['count'], 1))),
                    hours=i % 24,
                )
                db.session.add(report)
                total += 1

        db.session.commit()
        print(f'Seeded {total} reports across {len(SEED_REPORTS)} addresses.')
        print()
        print('Test these addresses:')
        print('─' * 60)
        for entry in SEED_REPORTS:
            print(f'  [{entry["address_type"]:10}] {entry["address_raw"]:45} ({entry["count"]} reports)')


if __name__ == '__main__':
    seed()
