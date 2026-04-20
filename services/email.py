"""Email sending. SMTP in production, logs in dev."""
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app

logger = logging.getLogger(__name__)


def send_email(to, subject, html_body, text_body=None):
    """Send an email. Returns True on success.

    If SMTP env vars aren't set, logs to stdout (dev mode).
    """
    mail_server = os.environ.get('MAIL_SERVER')
    mail_from = os.environ.get('MAIL_FROM', 'noreply@scamguard.io')

    if not mail_server:
        logger.info('=== EMAIL (no SMTP configured) ===')
        logger.info('To: %s', to)
        logger.info('From: %s', mail_from)
        logger.info('Subject: %s', subject)
        logger.info('Body:\n%s', text_body or html_body)
        logger.info('=== END EMAIL ===')
        return True

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = mail_from
    msg['To'] = to

    if text_body:
        msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    port = int(os.environ.get('MAIL_PORT', 587))
    username = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')

    try:
        with smtplib.SMTP(mail_server, port) as server:
            server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error('Failed to send email to %s: %s', to, e)
        return False


def send_verification_email(user, code):
    subject = 'Verify your ScamGuard account'
    html = f'''
    <p>Hi {user.name or 'there'},</p>
    <p>Your ScamGuard verification code is:</p>
    <p style="font-size:24px;font-weight:bold;letter-spacing:4px;">{code}</p>
    <p>This code expires in 15 minutes.</p>
    <p>If you didn't sign up for ScamGuard, you can safely ignore this email.</p>
    '''
    text = f'Your ScamGuard verification code is: {code}\n\nThis code expires in 15 minutes.'
    return send_email(user.email, subject, html, text)


def send_password_reset_email(user, reset_url):
    subject = 'Reset your ScamGuard password'
    html = f'''
    <p>Hi {user.name or 'there'},</p>
    <p>Click the link below to reset your password:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p>This link expires in 1 hour. If you didn't request a password reset, ignore this email.</p>
    '''
    text = f'Reset your password: {reset_url}\n\nThis link expires in 1 hour.'
    return send_email(user.email, subject, html, text)
