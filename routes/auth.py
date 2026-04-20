from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, current_app)
from flask_login import login_user, logout_user, login_required, current_user

from extensions import db, limiter
from models.user import User
from services.auth_service import (register_user, verify_email, resend_verification,
                                    start_password_reset, complete_password_reset)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth',
                    template_folder='../templates')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('app.overview'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip() or None

        user, error = register_user(email, password, name)
        if error:
            flash(error, 'error')
            return render_template('auth/register.html', email=email, name=name)

        login_user(user)
        return redirect(url_for('auth.verify_prompt'))

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('10/minute')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('app.overview'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password) or not user.is_active:
            flash('Invalid email or password.', 'error')
            return render_template('auth/login.html', email=email)

        from datetime import datetime, timezone
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()

        login_user(user, remember=True)
        next_url = request.args.get('next')
        if next_url and next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('app.overview'))

    return render_template('auth/login.html')


@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('marketing.landing'))


@auth_bp.route('/verify', methods=['GET', 'POST'])
@login_required
def verify_prompt():
    if current_user.is_email_verified:
        return redirect(url_for('app.overview'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        ok, error = verify_email(current_user, code)
        if not ok:
            flash(error, 'error')
            return render_template('auth/verify_prompt.html')
        flash('Email verified successfully!', 'success')
        return redirect(url_for('app.overview'))

    return render_template('auth/verify_prompt.html')


@auth_bp.route('/resend-verification', methods=['POST'])
@login_required
@limiter.limit('3/hour')
def resend():
    ok, error = resend_verification(current_user)
    flash(error or 'Verification code resent.', 'error' if error else 'success')
    return redirect(url_for('auth.verify_prompt'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('5/hour')
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        base_url = current_app.config.get('APP_BASE_URL', request.host_url.rstrip('/'))
        start_password_reset(email, base_url)
        flash('If an account exists for that email, a reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgot.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset.html', token=token)

        ok, error = complete_password_reset(token, password)
        if not ok:
            flash(error, 'error')
            return render_template('auth/reset.html', token=token)

        flash('Password reset. Please log in with your new password.', 'success')
        return redirect(url_for('auth.login'))

    # GET: verify token is valid before showing form
    if not User.verify_reset_token(token):
        flash('This reset link is invalid or has expired.', 'error')
        return redirect(url_for('auth.forgot_password'))

    return render_template('auth/reset.html', token=token)
