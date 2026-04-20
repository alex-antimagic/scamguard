from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id):
    from models.user import User
    return User.query.get(int(user_id))
