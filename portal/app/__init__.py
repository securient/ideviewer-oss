"""
IDE Viewer Portal - Flask Application Factory.
"""

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Track when the portal started — used for missing host grace period.
# Defined inline rather than imported from app.models, which imports this
# module for `db` and would make the import circular. Must stay timezone-aware:
# it is compared against values read back from timestamptz columns, and mixing
# aware and naive datetimes raises TypeError.
PORTAL_START_TIME = datetime.now(timezone.utc)
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
    # The portal runs on PostgreSQL in every environment. Validate before any
    # extension binds an engine, so a misconfiguration fails at boot with an
    # actionable message instead of surfacing later as a connection error.
    _validate_database_uri(app)

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
    
    # Snapshot both flags before touching the database.
    #
    # migrations/env.py sets SKIP_DB_INIT=1 in os.environ so that Alembic
    # invoking the app factory doesn't recurse into schema setup. That module
    # is imported by _init_database's upgrade() call, which means reading the
    # variable a second time afterwards sees Alembic's value, not the
    # operator's — and the default admin user was silently never created on any
    # fresh database the app migrated itself. Docker masks it: entrypoint.sh
    # migrates in a separate process and sets MIGRATIONS_DONE, so the factory
    # never imports env.py.
    skip_db_init = bool(os.environ.get('SKIP_DB_INIT'))
    migrations_done = bool(os.environ.get('MIGRATIONS_DONE'))

    # Database initialization — skip during migration commands and when entrypoint already ran migrations
    if not skip_db_init and not migrations_done:
        with app.app_context():
            _init_database(db)

    # Default user creation — runs even when the entrypoint already migrated.
    # Shares the boot lock so concurrent workers can't race to insert the same
    # admin account and trip the unique constraint on one of them.
    if not skip_db_init:
        with app.app_context():
            with _boot_lock(db):
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


def _validate_database_uri(app):
    """Reject anything that isn't a usable PostgreSQL URL."""
    uri = app.config.get('SQLALCHEMY_DATABASE_URI') or ''

    if not uri:
        raise ValueError(
            "DATABASE_URL is required — the portal runs on PostgreSQL. Set e.g. "
            "DATABASE_URL=postgresql://ideviewer:PASSWORD@localhost:5432/ideviewer "
            "(./start.sh provisions one for local development, and "
            "docker-compose.yml provides one for --docker)."
        )

    if uri.startswith('sqlite'):
        raise ValueError(
            "SQLite is no longer supported — the portal runs on PostgreSQL only. "
            "DATABASE_URL is set to a sqlite:// URL; check portal/.env for a "
            "stale value left over from an older release."
        )


# Arbitrary but stable 64-bit key for the boot-time schema lock.
_MIGRATION_LOCK_KEY = 0x1DE71E1E5C4E3A01 - (1 << 63)


@contextmanager
def _boot_lock(database):
    """Serialise boot-time schema work across processes.

    Gunicorn starts N workers concurrently and each one runs the app factory,
    so without this every worker races to apply migrations and to create the
    default admin user against the same database. A session-scoped Postgres
    advisory lock means the first worker does the work and the rest block,
    then find nothing left to do.

    The lock is held on its own AUTOCOMMIT connection so it survives the
    transactions that ``upgrade()`` opens and commits on other connections.
    """
    with database.engine.connect() as conn:
        conn = conn.execution_options(isolation_level='AUTOCOMMIT')
        conn.exec_driver_sql('SELECT pg_advisory_lock(%s)', (_MIGRATION_LOCK_KEY,))
        try:
            yield
        finally:
            conn.exec_driver_sql('SELECT pg_advisory_unlock(%s)', (_MIGRATION_LOCK_KEY,))


def _init_database(database):
    """Bring the schema up to the migration head.

    Alembic is the only path by which schema comes into existence. The old
    create_all() fallback is gone: it could bring up a database that matched
    the models but had no alembic_version row, leaving an install that no
    future migration could safely touch.
    """
    from flask_migrate import upgrade

    with _boot_lock(database):
        upgrade(directory=_migrations_directory())


def _migrations_directory():
    """Absolute path to the Alembic directory.

    Flask-Migrate resolves a relative directory against the working directory,
    not the app package, so callers that don't happen to run from portal/ —
    pytest, for one — need this spelled out.
    """
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'migrations')



def _create_default_user(database):
    """Create the initial admin user if no users exist.

    The password comes from IDEVIEWER_ADMIN_PASSWORD. If that is unset we
    generate a strong random one and log it once (operators retrieve it
    from the startup logs) rather than shipping a hardcoded credential.
    Either way the account is flagged must_change_password.
    """
    import logging
    import secrets as _secrets
    from app.models import User, utcnow

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
