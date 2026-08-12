"""
Configuration for IDE Viewer Portal.
"""

import os
from datetime import timedelta


def normalize_database_url(url: str) -> str:
    """Normalise a DATABASE_URL into a SQLAlchemy-usable form.

    Heroku/Cloud Run hand out ``postgres://``, which is not a registered
    SQLAlchemy dialect name; rewrite it to ``postgresql://``. Empty values
    pass through untouched so the missing-config error is raised by
    ``create_app`` with a useful message rather than here at import time.
    """
    if url.startswith('postgres://'):
        return url.replace('postgres://', 'postgresql://', 1)
    return url


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Database — PostgreSQL only, in every environment.
    #
    # There is deliberately no fallback. A local file database on a different
    # engine from the one we ship is how dev/prod divergence starts: for most
    # of this project's life the test suite ran on SQLite, which silently
    # disables foreign-key enforcement, so no FK in the schema was ever
    # checked. An unset DATABASE_URL is a configuration error, surfaced by
    # create_app() with instructions.
    SQLALCHEMY_DATABASE_URI = normalize_database_url(os.environ.get('DATABASE_URL', ''))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Portal settings
    PORTAL_NAME = 'IDE Viewer'
    PORTAL_URL = os.environ.get('PORTAL_URL') or 'http://localhost:5000'
    
    # API settings
    API_RATE_LIMIT = 100  # requests per minute

    # Google OAuth settings
    # Get these from: https://console.cloud.google.com/apis/credentials
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

    # Local login control
    # Set to 'true' to disable username/password login entirely
    # Set to 'auto' to disable local login automatically when Google OAuth is configured
    # Set to 'false' (default) to always allow local login
    DISABLE_LOCAL_LOGIN = os.environ.get('DISABLE_LOCAL_LOGIN', 'false').lower()


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    # SQLAlchemy engine options tuned for RDS db.t3.micro (~100 max_connections).
    # Conservative per-process pool keeps headroom for multiple ECS tasks * gunicorn workers.
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "5")),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "5")),
        "pool_pre_ping": True,
        "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", "1800")),
    }

    # Session security — SECURE cookies only when HTTPS is available
    # Set FORCE_HTTPS=true when you have a custom domain with SSL
    SESSION_COOKIE_SECURE = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Proxy support (for Cloud Run, ECS behind load balancer)
    PREFERRED_URL_SCHEME = 'https' if os.environ.get('FORCE_HTTPS', 'false').lower() == 'true' else 'http'


class TestingConfig(Config):
    """Testing configuration.

    The suite truncates tables between tests, so it must never inherit a URL
    that could point at a database someone cares about. TEST_DATABASE_URL is
    authoritative; conftest derives one from DATABASE_URL (by suffixing the
    database name) rather than reusing it directly, so pointing the portal at
    a real database cannot cause pytest to wipe it.
    """
    TESTING = True
    SQLALCHEMY_DATABASE_URI = normalize_database_url(
        os.environ.get('TEST_DATABASE_URL') or ''
    )


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
