"""
Shared test fixtures for IDEViewer tests.
"""

import os
import sys
import uuid
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

# Ensure the portal package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "portal"))

from ideviewer.models import (
    IDE, IDEType, Extension, Permission, ScanResult,
)
from ideviewer.secrets_scanner import SecretFinding, SecretsResult
from ideviewer.dependency_scanner import Package, DependencyResult


# ──────────────────────────────────────────────
# Data‑model fixtures (used by many test files)
# ──────────────────────────────────────────────

@pytest.fixture
def sample_permission():
    return Permission(name="fileSystem", description="Access the file system", is_dangerous=True)


@pytest.fixture
def safe_permission():
    return Permission(name="colors", description="Colour themes", is_dangerous=False)


@pytest.fixture
def sample_extension(sample_permission, safe_permission):
    return Extension(
        id="pub.dangerous-ext",
        name="Dangerous Extension",
        version="2.1.0",
        publisher="evil-corp",
        permissions=[sample_permission, safe_permission],
    )


@pytest.fixture
def safe_extension(safe_permission):
    return Extension(
        id="pub.safe-ext",
        name="Safe Extension",
        version="1.0.0",
        publisher="good-corp",
        permissions=[safe_permission],
    )


@pytest.fixture
def sample_ide(sample_extension, safe_extension):
    return IDE(
        ide_type=IDEType.VSCODE,
        name="Visual Studio Code",
        version="1.85.0",
        install_path="/usr/local/bin/code",
        extensions=[sample_extension, safe_extension],
        is_running=True,
    )


@pytest.fixture
def sample_scan_result(sample_ide):
    return ScanResult(
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        platform="Darwin 23.0",
        ides=[sample_ide],
    )


@pytest.fixture
def sample_secret_finding():
    return SecretFinding(
        file_path="/home/user/project/.env",
        secret_type="ethereum_private_key",
        variable_name="PRIVATE_KEY",
        line_number=3,
        severity="critical",
        description="Plaintext Ethereum private key detected.",
        recommendation="Use encrypted keystores.",
    )


@pytest.fixture
def sample_secrets_result(sample_secret_finding):
    return SecretsResult(
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        findings=[sample_secret_finding],
        scanned_paths=["/home/user/project/.env"],
    )


@pytest.fixture
def sample_package():
    return Package(
        name="requests",
        version="2.31.0",
        package_manager="pip",
        install_type="global",
    )


@pytest.fixture
def sample_dependency_result(sample_package):
    return DependencyResult(
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        packages=[sample_package],
        package_managers_found=["pip"],
        scanned_projects=["/home/user/project"],
    )


# ──────────────────────────────────────────────
# Flask portal fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def portal_app():
    """Create and configure a Flask test application with in-memory SQLite."""
    os.environ.pop("FLASK_CONFIG", None)
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("SECRET_KEY", None)

    from app import create_app, db as _db
    app = create_app("testing")

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def portal_db(portal_app):
    """Provide the SQLAlchemy db instance bound to the test app context."""
    from app import db as _db
    with portal_app.app_context():
        yield _db


@pytest.fixture
def portal_client(portal_app):
    """Flask test client for the portal."""
    return portal_app.test_client()


@pytest.fixture
def test_user(portal_app, portal_db):
    """Create a test user."""
    from app.models import User
    with portal_app.app_context():
        user = User(email="test@example.com", username="testuser")
        user.set_password("password123")
        portal_db.session.add(user)
        portal_db.session.commit()
        # Re-query to ensure it's attached to the session
        user = User.query.filter_by(email="test@example.com").first()
        yield user


@pytest.fixture
def test_customer_key(portal_app, portal_db, test_user):
    """Create a test customer key."""
    from app.models import CustomerKey
    with portal_app.app_context():
        key = CustomerKey(
            key=str(uuid.uuid4()),
            name="Test Key",
            user_id=test_user.id,
            max_hosts=5,
        )
        portal_db.session.add(key)
        portal_db.session.commit()
        key = CustomerKey.query.filter_by(name="Test Key").first()
        yield key


@pytest.fixture
def test_host(portal_app, portal_db, test_customer_key):
    """Create a test host."""
    from app.models import Host
    with portal_app.app_context():
        host = Host(
            hostname="test-machine",
            ip_address="192.168.1.100",
            platform="Darwin 23.0",
            customer_key_id=test_customer_key.id,
        )
        portal_db.session.add(host)
        portal_db.session.commit()
        host = Host.query.filter_by(hostname="test-machine").first()
        yield host


@pytest.fixture
def test_scan_report(portal_app, portal_db, test_host):
    """Create a test scan report."""
    from app.models import ScanReport
    with portal_app.app_context():
        report = ScanReport(
            host_id=test_host.id,
            scan_data={
                "ides": [
                    {
                        "name": "VS Code",
                        "version": "1.85.0",
                        "extensions": [
                            {
                                "id": "pub.test-ext",
                                "name": "Test Extension",
                                "version": "1.0.0",
                                "publisher": "test-pub",
                                "permissions": [
                                    {"name": "fileSystem", "is_dangerous": True}
                                ],
                            }
                        ],
                    }
                ],
                "total_ides": 1,
                "total_extensions": 1,
            },
            total_ides=1,
            total_extensions=1,
            dangerous_extensions=1,
        )
        portal_db.session.add(report)
        portal_db.session.commit()
        report = ScanReport.query.first()
        yield report


@pytest.fixture
def logged_in_client(portal_app, portal_client, test_user):
    """A test client that is already logged in."""
    with portal_app.app_context():
        with portal_client.session_transaction() as sess:
            sess["_user_id"] = str(test_user.id)
        yield portal_client
