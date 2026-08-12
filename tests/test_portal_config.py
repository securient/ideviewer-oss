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

    def test_default_secret_key(self):
        from config import DevelopmentConfig
        cfg = DevelopmentConfig()
        assert cfg.SECRET_KEY is not None
        assert len(cfg.SECRET_KEY) > 0

    def test_unset_database_url_has_no_fallback(self):
        # config.py binds SQLALCHEMY_DATABASE_URI at class-definition time, so
        # the value depends on the environment present when the module was
        # first imported. CI exports DATABASE_URL for the postgres service,
        # which meant this asserted against the ambient env rather than the
        # documented default. Reload with the var removed, then restore both
        # the env and the module so later tests see the real environment.
        #
        # The portal is PostgreSQL-only: an unset DATABASE_URL must yield an
        # empty URI so create_app raises, never a local file database on a
        # different engine.
        import importlib
        import config as config_module

        saved = os.environ.pop("DATABASE_URL", None)
        try:
            importlib.reload(config_module)
            cfg = config_module.DevelopmentConfig()
            assert cfg.SQLALCHEMY_DATABASE_URI == ""
        finally:
            if saved is not None:
                os.environ["DATABASE_URL"] = saved
            importlib.reload(config_module)

    def test_postgres_scheme_is_normalized(self):
        from config import normalize_database_url

        assert normalize_database_url("postgres://u:p@h:5432/d") == "postgresql://u:p@h:5432/d"
        assert normalize_database_url("postgresql://u:p@h:5432/d") == "postgresql://u:p@h:5432/d"
        assert normalize_database_url("") == ""

    def test_google_oauth_disabled_by_default(self, monkeypatch):
        # Ensure env vars are unset so we test true defaults
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
        import importlib
        import config as config_module
        importlib.reload(config_module)
        cfg = config_module.DevelopmentConfig()
        # DevelopmentConfig has no GOOGLE_OAUTH_ENABLED flag; OAuth is
        # considered disabled when client id/secret are unset.
        assert cfg.GOOGLE_CLIENT_ID is None
        assert cfg.GOOGLE_CLIENT_SECRET is None


class TestProductionConfig:
    """Test ProductionConfig."""

    def test_import_does_not_crash(self):
        """ProductionConfig class should load without error (validation happens in create_app)."""
        from config import ProductionConfig
        cfg = ProductionConfig()
        assert cfg.DEBUG is False

    # NOTE: SESSION_COOKIE_SECURE is currently gated on FORCE_HTTPS=true.
    # Making secure-by-default in production is on the Sprint 2 backlog.
    def test_session_cookie_secure_when_https_forced(self, monkeypatch):
        monkeypatch.setenv("FORCE_HTTPS", "true")
        import importlib
        import config as config_module
        importlib.reload(config_module)
        assert config_module.ProductionConfig.SESSION_COOKIE_SECURE is True
        assert config_module.ProductionConfig.SESSION_COOKIE_HTTPONLY is True

    def test_session_cookie_insecure_when_https_not_forced(self, monkeypatch):
        monkeypatch.delenv("FORCE_HTTPS", raising=False)
        import importlib
        import config as config_module
        importlib.reload(config_module)
        assert config_module.ProductionConfig.SESSION_COOKIE_SECURE is False
        assert config_module.ProductionConfig.SESSION_COOKIE_HTTPONLY is True


class TestTestingConfig:
    """Test TestingConfig."""

    def test_testing_flag(self, portal_schema):
        # portal_schema exports TEST_DATABASE_URL; reload so the class picks it
        # up, since config binds the URI at import time.
        import importlib
        import config as config_module

        importlib.reload(config_module)
        cfg = config_module.TestingConfig()
        assert cfg.TESTING is True
        assert cfg.SQLALCHEMY_DATABASE_URI.startswith("postgresql://")

    def test_testing_never_falls_back_to_database_url(self):
        # DATABASE_URL points at the real portal database. TestingConfig must
        # not inherit it — the suite truncates tables between tests.
        #
        # Restore the environment before reloading in the finally block:
        # monkeypatch undoes its changes only after the test returns, so a
        # reload there would rebind config against the patched environment and
        # leak an empty URI into every later test.
        import importlib
        import config as config_module

        saved_db = os.environ.get("DATABASE_URL")
        saved_test = os.environ.pop("TEST_DATABASE_URL", None)
        os.environ["DATABASE_URL"] = "postgresql://u:p@h:5432/production_data"
        try:
            importlib.reload(config_module)
            assert config_module.TestingConfig().SQLALCHEMY_DATABASE_URI == ""
        finally:
            if saved_db is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = saved_db
            if saved_test is not None:
                os.environ["TEST_DATABASE_URL"] = saved_test
            importlib.reload(config_module)


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

    def test_production_without_secret_key_raises(self, monkeypatch):
        """Production config without SECRET_KEY should raise ValueError."""
        # Popping the env var has no effect: ProductionConfig.SECRET_KEY is bound
        # when config.py is imported, and create_app reads the class attribute
        # via app.config.from_object. CI exports SECRET_KEY, so this previously
        # never raised and the check went untested.
        #
        # Patch the class create_app actually consults, reached through app's own
        # `config` dict. app/__init__.py does `from config import config`, binding
        # that dict at import; other tests here reload the config module, which
        # rebinds config.ProductionConfig to a new object while app keeps the
        # original — so patching config.ProductionConfig directly works in
        # isolation but silently misses once the suite runs in order.
        import app as app_module

        monkeypatch.setattr(app_module.config["production"], "SECRET_KEY", "")
        from app import create_app
        with pytest.raises(ValueError, match="SECRET_KEY"):
            create_app("production")

    def test_production_without_env_vars_raises(self, monkeypatch):
        """Production config without required env vars should raise ValueError."""
        import app as app_module

        prod = app_module.config["production"]
        monkeypatch.setattr(prod, "SECRET_KEY", "")
        monkeypatch.setattr(prod, "SQLALCHEMY_DATABASE_URI", "")
        from app import create_app
        with pytest.raises(ValueError):
            create_app("production")
