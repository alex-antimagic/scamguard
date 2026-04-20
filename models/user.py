import random
import uuid
from datetime import datetime, timezone, timedelta

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120))
    role = db.Column(db.String(20), nullable=False, default='user')
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Email verification
    email_verified_at = db.Column(db.DateTime)
    verify_code = db.Column(db.String(6))
    verify_expires_at = db.Column(db.DateTime)

    # Stripe
    stripe_customer_id = db.Column(db.String(255), unique=True)

    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))

    api_keys = db.relationship('ApiKey', backref='user', lazy='dynamic',
                                cascade='all, delete-orphan')
    subscription = db.relationship('Subscription', backref='user', uselist=False,
                                    cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_verify_code(self):
        code = f'{random.randint(0, 999999):06d}'
        self.verify_code = code
        self.verify_expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        return code

    def check_verify_code(self, code):
        if not self.verify_code or not self.verify_expires_at:
            return False
        if datetime.now(timezone.utc) > self.verify_expires_at.replace(tzinfo=timezone.utc):
            return False
        return self.verify_code == str(code)

    @property
    def is_email_verified(self):
        return self.email_verified_at is not None

    @property
    def is_admin(self):
        return self.role == 'admin'

    def get_reset_token(self, expires_sec=3600):
        from itsdangerous import URLSafeTimedSerializer
        from flask import current_app
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return s.dumps(self.id, salt='password-reset')

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
        from flask import current_app
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='password-reset', max_age=expires_sec)
        except (SignatureExpired, BadSignature):
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f'<User {self.email}>'
