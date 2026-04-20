import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # External APIs
    GOOGLE_WEB_RISK_API_KEY = os.environ.get('GOOGLE_WEB_RISK_API_KEY', '')
    GOOGLE_CSE_API_KEY = os.environ.get('GOOGLE_CSE_API_KEY', '')
    GOOGLE_CSE_ENGINE_ID = os.environ.get('GOOGLE_CSE_ENGINE_ID', '')

    # Analysis
    SCAN_CACHE_TTL = int(os.environ.get('SCAN_CACHE_TTL', 3600))
    ANALYSIS_TIMEOUT = int(os.environ.get('ANALYSIS_TIMEOUT', 10))

    # Public base URL for email links
    APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5555')

    # Dev-only: override verification code that always works.
    # Useful when SMTP isn't configured. Unset in real production.
    DEV_VERIFY_CODE = os.environ.get('DEV_VERIFY_CODE', '')

    # Stripe
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    STRIPE_STARTER_PRICE_ID = os.environ.get('STRIPE_STARTER_PRICE_ID', '')
    STRIPE_PRO_PRICE_ID = os.environ.get('STRIPE_PRO_PRICE_ID', '')

    # Rate limiting — Heroku Redis uses self-signed certs
    _redis_url = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_STORAGE_URI = _redis_url
    RATELIMIT_STORAGE_OPTIONS = {}

    if _redis_url.startswith('rediss://'):
        import ssl
        RATELIMIT_STORAGE_OPTIONS = {
            'ssl_cert_reqs': ssl.CERT_NONE,
        }


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 'sqlite:///scamguard.db'
    )


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '')

    @staticmethod
    def init_app(app):
        # Heroku uses postgres:// but SQLAlchemy needs postgresql://
        uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if uri.startswith('postgres://'):
            app.config['SQLALCHEMY_DATABASE_URI'] = uri.replace(
                'postgres://', 'postgresql://', 1
            )
        # Fail loudly if SECRET_KEY is weak in production
        if app.config.get('SECRET_KEY') in (None, '', 'dev-secret-change-me'):
            raise RuntimeError('SECRET_KEY must be set to a strong random value in production')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
