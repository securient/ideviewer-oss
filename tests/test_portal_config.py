"""Tests for portal configuration."""

import os
import pytest


class TestDevelopmentConfig:
    """Test that DevelopmentConfig works without env vars."""

    def test_import_does_not_crash(self):
        """DevelopmentConfig should import and instantiate without env vars."""
        from config import DevelopmentConfig
        cfg = DevelopmentConfig()
        assert cfg.DEBUG is True
        assert cfg.SQLALCHEMY_TRACK_MODIFICATIONS is False
        assert cfg.FREE_TIER_HOST_LIMIT == 5

    def test_default_secret_key(self):
        from config import DevelopmentConfig
        cfg = DevelopmentConfig()
        assert cfg.SECRET_KEY is not None
        assert len(cfg.SECRET_KEY) > 0

    def test_default_database_uri(self):
        from config import DevelopmentConfig
        cfg = DevelopmentConfig()
        assert "sqlite" in cfg.SQLALCHEMY_DATABASE_URI

    def test_google_oauth_disabled_by_default(self):
        from config import DevelopmentConfig
        cfg = DevelopmentConfig()
        assert cfg.GOOGLE_OAUTH_ENABLED is False


class TestProductionConfig:
    """Test ProductionConfig."""

    def test_import_does_not_crash(self):
        """ProductionConfig class should load without error (validation happens in create_app)."""
        from config import ProductionConfig
        cfg = ProductionConfig()
        assert cfg.DEBUG is False

    def test_session_cookie_secure(self):
        from config import ProductionConfig
        assert ProductionConfig.SESSION_COOKIE_SECURE is True
        assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True


class TestTestingConfig:
    """Test TestingConfig."""

    def test_testing_flag(self):
        from config import TestingConfig
        cfg = TestingConfig()
        assert cfg.TESTING is True
        assert cfg.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:"


class TestConfigDict:
    """Test the config dict mapping."""

    def test_config_keys(self):
        from config import config
        assert "development" in config
        assert "production" in config
        assert "testing" in config
        assert "default" in config


class TestAppFactory:
    """Test create_app with different configs."""

    def test_create_testing_app(self):
        from app import create_app
        app = create_app("testing")
        assert app.config["TESTING"] is True

    def test_create_development_app(self):
        from app import create_app
        app = create_app("development")
        assert app.config["DEBUG"] is True

    def test_production_without_secret_key_raises(self):
        """Production config without SECRET_KEY should raise ValueError."""
        os.environ.pop("SECRET_KEY", None)
        os.environ.pop("DATABASE_URL", None)
        from app import create_app
        with pytest.raises(ValueError, match="SECRET_KEY"):
            create_app("production")

    def test_production_without_env_vars_raises(self):
        """Production config without required env vars should raise ValueError."""
        os.environ.pop("SECRET_KEY", None)
        os.environ.pop("DATABASE_URL", None)
        from app import create_app
        with pytest.raises(ValueError):
            create_app("production")
