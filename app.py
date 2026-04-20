import os

import sentry_sdk
from flask import Flask
from sentry_sdk.integrations.flask import FlaskIntegration
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from extensions import db, migrate, limiter, cache, login_manager, csrf


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    if hasattr(config[config_name], 'init_app'):
        config[config_name].init_app(app)

    # Trust proxy headers (Heroku uses 1 proxy)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Sentry — init early so all errors are captured including extension init
    sentry_dsn = os.environ.get('SENTRY_DSN')
    if sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=0.1,
            environment=config_name,
        )

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    cache.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://js.stripe.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
                "font-src https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https://api.stripe.com; "
                "frame-src https://js.stripe.com https://hooks.stripe.com; "
                "frame-ancestors 'none';"
            )
        return response

    # Error handlers — ensure all 500s reach Sentry
    @app.errorhandler(500)
    def internal_error(e):
        sentry_sdk.capture_exception(e.original_exception if hasattr(e, 'original_exception') else e)
        return {'error': 'Internal server error'}, 500

    @app.errorhandler(429)
    def rate_limited(e):
        return {'error': 'Rate limit exceeded. Please slow down.'}, 429

    # Import models so Alembic sees them
    from models import scan, report, user, api_key, subscription, usage_event  # noqa: F401

    # Blueprints
    from routes.api import api_bp
    from routes.portal import portal_bp
    from routes.health import health_bp
    from routes.auth import auth_bp
    from routes.marketing import marketing_bp
    from routes.app import app_bp
    from routes.billing import billing_bp
    from routes.webhooks import webhooks_bp

    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(portal_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(marketing_bp)
    app.register_blueprint(app_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(webhooks_bp)

    # CSRF exemption for the JSON API and Stripe webhook
    csrf.exempt(api_bp)
    csrf.exempt(webhooks_bp)

    # CLI commands
    from cli import register_commands
    register_commands(app)

    return app
