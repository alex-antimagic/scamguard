"""Auth service: registration, email verification, password reset."""
from datetime import datetime, timezone

from email_validator import validate_email, EmailNotValidError

from extensions import db
from models.user import User
from models.subscription import Subscription, TIER_FREE, STATUS_ACTIVE
from services.email import send_verification_email, send_password_reset_email
from services.plan_gating import get_plan


def register_user(email, password, name=None):
    """Register a new user. Creates a free-tier subscription.

    Returns (user, error_message). If error_message is set, user is None.
    """
    try:
        valid = validate_email(email, check_deliverability=False)
        email = valid.normalized.lower()
    except EmailNotValidError as e:
        return None, str(e)

    if len(password) < 8:
        return None, 'Password must be at least 8 characters.'

    existing = User.query.filter_by(email=email).first()
    if existing:
        return None, 'An account with this email already exists.'

    user = User(email=email, name=name)
    user.set_password(password)
    code = user.set_verify_code()

    db.session.add(user)
    db.session.flush()  # get user.id

    # Create free-tier subscription
    free_plan = get_plan(TIER_FREE)
    sub = Subscription(
        user_id=user.id,
        plan_tier=TIER_FREE,
        status=STATUS_ACTIVE,
        scans_included=free_plan['scans_included'],
        overage_rate_cents=0,
    )
    db.session.add(sub)
    db.session.commit()

    send_verification_email(user, code)
    return user, None


def verify_email(user, code):
    from flask import current_app
    dev_code = current_app.config.get('DEV_VERIFY_CODE', '')
    is_valid = user.check_verify_code(code) or (dev_code and str(code) == dev_code)
    if not is_valid:
        return False, 'Invalid or expired verification code.'
    user.email_verified_at = datetime.now(timezone.utc)
    user.verify_code = None
    user.verify_expires_at = None
    db.session.commit()
    return True, None


def resend_verification(user):
    if user.is_email_verified:
        return False, 'Email is already verified.'
    code = user.set_verify_code()
    db.session.commit()
    send_verification_email(user, code)
    return True, None


def start_password_reset(email, base_url):
    user = User.query.filter_by(email=email.lower()).first()
    # Always return success to avoid account enumeration
    if user:
        token = user.get_reset_token()
        reset_url = f'{base_url.rstrip("/")}/auth/reset-password/{token}'
        send_password_reset_email(user, reset_url)
    return True


def complete_password_reset(token, new_password):
    user = User.verify_reset_token(token)
    if not user:
        return False, 'This reset link is invalid or has expired.'
    if len(new_password) < 8:
        return False, 'Password must be at least 8 characters.'
    user.set_password(new_password)
    db.session.commit()
    return True, None
