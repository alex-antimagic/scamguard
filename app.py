import os

import sentry_sdk
from flask import Flask
from sentry_sdk.integrations.flask import FlaskIntegration

from config import config
from extensions import db, migrate, limiter, cache


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    if hasattr(config[config_name], 'init_app'):
        config[config_name].init_app(app)

    # Sentry
    sentry_dsn = os.environ.get('SENTRY_DSN')
    if sentry_dsn:
        sentry_sdk.init(dsn=sentry_dsn, integrations=[FlaskIntegration()])

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    cache.init_app(app)

    # Import models so Alembic sees them
    from models import scan, report  # noqa: F401

    # Blueprints
    from routes.api import api_bp
    from routes.portal import portal_bp
    from routes.health import health_bp

    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(portal_bp)
    app.register_blueprint(health_bp)

    return app
