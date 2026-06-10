"""
IDE Viewer Portal - Flask Application Factory.
"""

import os
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Track when the portal started — used for missing host grace period
PORTAL_START_TIME = datetime.utcnow()
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth

from config import config

# Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
oauth = OAuth()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


def create_app(config_name=None):
    """Application factory."""
    
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    app.config.from_object(config[config_name])

    # Validate production config
    if config_name == 'production':
        secret = app.config.get('SECRET_KEY')
        if not secret:
            raise ValueError("SECRET_KEY environment variable is required in production")
        # Refuse to boot production with a known-insecure secret. Local/dev
        # stacks that intentionally run FLASK_CONFIG=production (e.g. docker
        # compose) can opt out with ALLOW_INSECURE_SECRET_KEY=1.
        insecure_secrets = {'dev-secret-key-change-in-production'}
        allow_insecure = os.environ.get('ALLOW_INSECURE_SECRET_KEY', '').lower() in ('1', 'true', 'yes')
        if secret in insecure_secrets and not allow_insecure:
            raise ValueError(
                "SECRET_KEY is set to a known insecure default. Set a strong "
                "SECRET_KEY (e.g. `openssl rand -base64 32`), or set "
                "ALLOW_INSECURE_SECRET_KEY=1 for local/dev use only."
            )
        if not app.config.get('SQLALCHEMY_DATABASE_URI'):
            raise ValueError("DATABASE_URL environment variable is required in production")

    # Ensure instance folder exists
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # Trust proxy headers when behind ALB/nginx (required for CSRF, OAuth redirects)
    if config_name == 'production':
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    oauth.init_app(app)

    # Initialise background job queue.
    # In testing mode we hard-skip even if a stray REDIS_URL is set in the
    # environment, unless PORTAL_TEST_USE_REDIS opts in explicitly.
    if config_name != "testing" or os.environ.get("PORTAL_TEST_USE_REDIS"):
        from app.queue import init_queue
        init_queue(app)
    
    # Register Google OAuth if configured
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
    
    # Enable CORS for API endpoints. The daemon authenticates with headers
    # (not cookies) and is not a browser, so a wildcard origin buys nothing
    # and only widens the browser attack surface. Default to same-origin
    # (no cross-origin allowed); operators opt specific origins in via
    # CORS_ORIGINS (comma-separated).
    _cors_env = os.environ.get('CORS_ORIGINS', '').strip()
    _cors_origins = [o.strip() for o in _cors_env.split(',') if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": _cors_origins}})
    
    # Register blueprints
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.api.routes import api_bp
    from app.observability import metrics_bp, init_json_logging

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(metrics_bp)

    # Exempt API and metrics blueprints from CSRF.
    csrf.exempt(api_bp)
    csrf.exempt(metrics_bp)

    # Observability: JSON logs in production, /metrics always exposed.
    app.config.setdefault('FLASK_CONFIG', config_name)
    init_json_logging(app)
    
    # Database initialization — skip during migration commands and when entrypoint already ran migrations
    if not os.environ.get('SKIP_DB_INIT') and not os.environ.get('MIGRATIONS_DONE'):
        with app.app_context():
            _init_database(db)

    # Default user creation — runs once even after entrypoint migrations (only first worker)
    if not os.environ.get('SKIP_DB_INIT'):
        with app.app_context():
            _create_default_user(db)
    
    # Security response headers. Applied everywhere; HSTS only when we know
    # the portal is served over HTTPS (FORCE_HTTPS), so local http:// demos
    # are unaffected.
    force_https = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('X-XSS-Protection', '0')
        if force_https:
            response.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains',
            )
        return response

    # Context processor to make config available in templates
    @app.context_processor
    def inject_config():
        """Inject configuration into templates."""
        google_oauth = bool(
            app.config.get('GOOGLE_CLIENT_ID') and
            app.config.get('GOOGLE_CLIENT_SECRET')
        )
        # Read DISABLE_LOCAL_LOGIN from env at runtime (not cached in config class)
        disable_mode = os.environ.get('DISABLE_LOCAL_LOGIN', app.config.get('DISABLE_LOCAL_LOGIN', 'false')).lower()
        local_login = True
        if disable_mode == 'true':
            local_login = False
        elif disable_mode == 'auto' and google_oauth:
            local_login = False

        class TemplateConfig:
            GOOGLE_OAUTH_ENABLED = google_oauth
            LOCAL_LOGIN_ENABLED = local_login
            PORTAL_NAME = app.config.get('PORTAL_NAME', 'IDE Viewer')

        return {'config': TemplateConfig}
    
    return app


def _init_database(database):
    """Initialize the database — use migrations if available, otherwise create_all."""
    try:
        # Check if alembic_version table exists (migrations have been run before)
        database.session.execute(database.text('SELECT 1 FROM alembic_version LIMIT 1'))
        database.session.rollback()
        # Migrations are tracked — run pending migrations
        from flask_migrate import upgrade
        upgrade()
    except Exception:
        database.session.rollback()
        # First run — check if migrations directory exists
        migrations_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'migrations', 'versions')
        if os.path.isdir(migrations_dir) and os.listdir(migrations_dir):
            # Migrations exist — run them from scratch
            from flask_migrate import upgrade
            upgrade()
        else:
            # No migrations — fallback to create_all (dev mode)
            database.create_all()



def _create_default_user(database):
    """Create the initial admin user if no users exist.

    The password comes from IDEVIEWER_ADMIN_PASSWORD. If that is unset we
    generate a strong random one and log it once (operators retrieve it
    from the startup logs) rather than shipping a hardcoded credential.
    Either way the account is flagged must_change_password.
    """
    import logging
    import secrets as _secrets
    from app.models import User

    if User.query.count() != 0:
        return

    username = os.environ.get('IDEVIEWER_ADMIN_USERNAME', 'admin')
    email = os.environ.get('IDEVIEWER_ADMIN_EMAIL', 'admin@localhost')
    password = os.environ.get('IDEVIEWER_ADMIN_PASSWORD')

    generated = False
    if not password:
        password = _secrets.token_urlsafe(18)
        generated = True

    user = User(
        username=username,
        email=email,
        must_change_password=True,
    )
    user.set_password(password)
    database.session.add(user)
    database.session.commit()

    if generated:
        logging.getLogger('ideviewer').warning(
            "Created initial admin user '%s' with a generated password: %s "
            "— log in and change it immediately. Set IDEVIEWER_ADMIN_PASSWORD "
            "to choose your own.",
            username, password,
        )


@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    from app.models import User
    return User.query.get(int(user_id))
