"""
Configuration for IDE Viewer Portal.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration."""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'ideviewer.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Portal settings
    PORTAL_NAME = 'IDE Viewer'
    PORTAL_URL = os.environ.get('PORTAL_URL') or 'http://localhost:5000'
    
    # API settings
    API_RATE_LIMIT = 100  # requests per minute

    # Host limit per customer key (default: 5, configurable via environment)
    FREE_TIER_HOST_LIMIT = int(os.environ.get('FREE_TIER_HOST_LIMIT', '5'))
    
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
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', '')

    # Handle Cloud Run/Heroku style DATABASE_URL (postgres:// -> postgresql://)
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)

    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Proxy support (for Cloud Run, ECS behind load balancer)
    PREFERRED_URL_SCHEME = 'https'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
