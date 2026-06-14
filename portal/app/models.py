"""
Database models for IDE Viewer Portal.
"""

import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from app import db


class User(UserMixin, db.Model):
    """User account model."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  # Nullable for OAuth users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    must_change_password = db.Column(db.Boolean, default=False)  # Force password change on first login

    # OAuth fields
    oauth_provider = db.Column(db.String(50))  # 'google', 'github', etc.
    oauth_id = db.Column(db.String(255))  # Provider's user ID
    avatar_url = db.Column(db.String(500))  # Profile picture URL
    
    # Relationships
    customer_keys = db.relationship('CustomerKey', backref='owner', lazy='dynamic')
    
    def set_password(self, password):
        """Hash and set password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_oauth_user(self):
        """Check if user signed up via OAuth."""
        return self.oauth_provider is not None
    
    @staticmethod
    def get_or_create_oauth_user(email, username, provider, oauth_id, avatar_url=None):
        """Get existing user or create new OAuth user."""
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if user exists
            if not user.oauth_provider:
                user.oauth_provider = provider
                user.oauth_id = oauth_id
            if avatar_url:
                user.avatar_url = avatar_url
            db.session.commit()
            return user
        
        # Create new user
        # Ensure unique username
        base_username = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        user = User(
            email=email,
            username=username,
            oauth_provider=provider,
            oauth_id=oauth_id,
            avatar_url=avatar_url
        )
        db.session.add(user)
        db.session.commit()
        return user
    
    def __repr__(self):
        return f'<User {self.username}>'


class CustomerKey(db.Model):
    """Customer API key for daemon authentication."""
    
    __tablename__ = 'customer_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(36), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)  # Friendly name for the key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    hosts = db.relationship('Host', backref='customer_key', lazy='dynamic')
    
    @staticmethod
    def generate_key():
        """Generate a new UUID key."""
        return str(uuid.uuid4())
    
    @property
    def host_count(self):
        """Get number of registered hosts."""
        return self.hosts.count()
    
    def __repr__(self):
        return f'<CustomerKey {self.key[:8]}...>'


class Host(db.Model):
    """Registered host/machine."""
    
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    # Public UUID for URLs (unguessable)
    public_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    platform = db.Column(db.String(100))
    customer_key_id = db.Column(db.Integer, db.ForeignKey('customer_keys.id'), nullable=False)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat_at = db.Column(db.DateTime)  # Last heartbeat from daemon
    daemon_version = db.Column(db.String(50))  # Daemon version
    is_active = db.Column(db.Boolean, default=True)
    last_realtime_event = db.Column(db.DateTime)  # Last real-time filesystem change event

    # Server-side integrity monitoring (Phase 1 B2). A host whose daemon stops
    # heartbeating is "silent" — the server raises one alert on the ok->silent
    # transition (deduped via this state) and resets it when a heartbeat returns.
    heartbeat_alarm_state = db.Column(db.String(16), default='ok')  # 'ok' | 'silent'
    silent_since = db.Column(db.DateTime, nullable=True)

    # Composite risk score v2 (Phase 1 B8). Denormalized 0-100 score + level,
    # recomputed from current state on each scan-report ingestion. See
    # app/risk_score.py for the (explainable, additive) model.
    risk_score = db.Column(db.Integer, nullable=True)
    risk_level_composite = db.Column(db.String(16), nullable=True)

    # Per-host enrollment token (T1.3). Only the sha256 hex digest is stored;
    # plaintext is returned exactly once at issue time.
    token_hash = db.Column(db.String(64), nullable=True, index=True)
    token_issued_at = db.Column(db.DateTime, nullable=True)
    token_revoked_at = db.Column(db.DateTime, nullable=True)

    # Unique constraint on hostname + customer_key
    __table_args__ = (
        db.UniqueConstraint('hostname', 'customer_key_id', name='unique_host_per_key'),
    )

    # Relationships
    scan_reports = db.relationship('ScanReport', backref='host', lazy='dynamic',
                                   order_by='desc(ScanReport.created_at)')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.public_id:
            self.public_id = str(uuid.uuid4())

    @property
    def latest_report(self):
        """Get the most recent scan report."""
        return self.scan_reports.first()

    # ────────────────────────────────────────────────────────────────
    # Per-host enrollment-token helpers
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_host_token():
        """Return ``(plaintext, sha256_hex)``. Plaintext is base64url, ~43 chars."""
        import base64
        import hashlib
        import secrets
        raw = secrets.token_bytes(32)
        plaintext = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
        sha = hashlib.sha256(plaintext.encode('ascii')).hexdigest()
        return plaintext, sha

    @staticmethod
    def hash_token(plaintext: str) -> str:
        """Return the sha256 hex digest of a token string."""
        import hashlib
        return hashlib.sha256(plaintext.encode('ascii')).hexdigest()

    def issue_token(self) -> str:
        """Issue a fresh token, store its hash, return plaintext."""
        plaintext, h = self.generate_host_token()
        self.token_hash = h
        self.token_issued_at = datetime.utcnow()
        self.token_revoked_at = None
        return plaintext

    def revoke_token(self) -> None:
        """Mark the current token as revoked."""
        self.token_revoked_at = datetime.utcnow()

    def token_is_valid(self) -> bool:
        """True iff the host has an active, unrevoked token and is itself active."""
        return (
            self.token_hash is not None
            and self.token_revoked_at is None
            and self.is_active
        )

    def __repr__(self):
        return f'<Host {self.hostname}>'


class ScanReport(db.Model):
    """Scan report from a host."""
    
    __tablename__ = 'scan_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Store the full scan data as JSON
    scan_data = db.Column(db.JSON, nullable=False)
    
    # Summary fields for quick queries
    total_ides = db.Column(db.Integer, default=0)
    total_extensions = db.Column(db.Integer, default=0)
    dangerous_extensions = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<ScanReport {self.id} for Host {self.host_id}>'


class ExtensionInfo(db.Model):
    """Cached extension information for quick dashboard queries."""
    
    __tablename__ = 'extension_info'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    scan_report_id = db.Column(db.Integer, db.ForeignKey('scan_reports.id'), nullable=False)
    
    # Extension details
    ide_name = db.Column(db.String(100), nullable=False)
    ide_version = db.Column(db.String(50))
    extension_id = db.Column(db.String(200), nullable=False)
    extension_name = db.Column(db.String(200), nullable=False)
    extension_version = db.Column(db.String(50))
    publisher = db.Column(db.String(200))
    maintainer = db.Column(db.String(200))
    
    # Risk assessment
    permissions = db.Column(db.JSON)  # List of permissions
    risk_level = db.Column(db.String(20))  # low, medium, high, critical
    is_dangerous = db.Column(db.Boolean, default=False)
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_extension_risk', 'risk_level', 'is_dangerous'),
        db.Index('idx_extension_host', 'host_id', 'ide_name'),
    )
    
    def __repr__(self):
        return f'<ExtensionInfo {self.extension_id}>'


class SecretFinding(db.Model):
    """Plaintext secret/credential findings from hosts."""
    
    __tablename__ = 'secret_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    scan_report_id = db.Column(db.Integer, db.ForeignKey('scan_reports.id'), nullable=False)
    
    # Finding details (NO actual secret values stored — only redacted!)
    file_path = db.Column(db.String(500), nullable=False)
    secret_type = db.Column(db.String(50), nullable=False)  # ethereum_private_key, mnemonic, aws_key, etc.
    variable_name = db.Column(db.String(200))
    line_number = db.Column(db.Integer)
    severity = db.Column(db.String(20), default='critical')  # critical, high, medium, low
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    redacted_value = db.Column(db.String(200), default='')  # e.g., "AKIA****XMPL"

    # Source: "filesystem" (current .env files) or "git_history" (committed secrets)
    source = db.Column(db.String(20), default='filesystem')
    commit_hash = db.Column(db.String(40))
    commit_author = db.Column(db.String(200))
    commit_date = db.Column(db.String(30))
    repo_path = db.Column(db.String(500))

    # Timestamps
    first_detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)

    # Relationships
    host = db.relationship('Host', backref=db.backref('secret_findings', lazy='dynamic'))

    # Indexes
    __table_args__ = (
        db.Index('idx_secret_type', 'secret_type'),
        db.Index('idx_secret_host', 'host_id', 'is_resolved'),
    )

    def to_dict(self):
        d = {
            'id': self.id,
            'file_path': self.file_path,
            'secret_type': self.secret_type,
            'variable_name': self.variable_name,
            'line_number': self.line_number,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'redacted_value': self.redacted_value or '',
            'source': self.source or 'filesystem',
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'is_resolved': self.is_resolved,
        }
        if self.source == 'git_history':
            d['commit_hash'] = self.commit_hash
            d['commit_author'] = self.commit_author
            d['commit_date'] = self.commit_date
            d['repo_path'] = self.repo_path
        return d
    
    def __repr__(self):
        return f'<SecretFinding {self.secret_type} in {self.file_path}>'


class PackageInfo(db.Model):
    """Installed package/dependency information from hosts."""
    
    __tablename__ = 'package_info'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    scan_report_id = db.Column(db.Integer, db.ForeignKey('scan_reports.id'), nullable=False)
    
    # Package details
    name = db.Column(db.String(200), nullable=False)
    version = db.Column(db.String(100))
    package_manager = db.Column(db.String(50), nullable=False)  # pip, npm, go, cargo, gem, composer, maven
    install_type = db.Column(db.String(20), default='project')  # global, project
    project_path = db.Column(db.String(500))
    lifecycle_hooks = db.Column(db.JSON)  # npm lifecycle hooks {preinstall: "...", postinstall: "..."}
    source_type = db.Column(db.String(20), default='project')  # project, global, extension
    source_extension = db.Column(db.String(200))  # Extension ID when source_type == 'extension'
    
    # Timestamps
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    host = db.relationship('Host', backref=db.backref('packages', lazy='dynamic'))
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_package_name', 'name'),
        db.Index('idx_package_manager', 'package_manager'),
        db.Index('idx_package_host', 'host_id', 'package_manager'),
        db.Index('idx_package_source', 'host_id', 'source_type'),
    )
    
    def to_dict(self):
        result = {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'package_manager': self.package_manager,
            'install_type': self.install_type,
            'project_path': self.project_path,
            'source_type': self.source_type or self.install_type,
            'source_extension': self.source_extension,
            'first_seen_at': self.first_seen_at.isoformat() if self.first_seen_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
        }
        if self.lifecycle_hooks:
            result['lifecycle_hooks'] = self.lifecycle_hooks
        return result
    
    def __repr__(self):
        return f'<PackageInfo {self.package_manager}:{self.name}@{self.version}>'


class ScanRequest(db.Model):
    """On-demand scan request from portal to daemon."""
    
    __tablename__ = 'scan_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Status: pending, connecting, scanning_ides, scanning_secrets, scanning_packages, completed, failed, timeout
    status = db.Column(db.String(30), default='pending', nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Progress log (JSON array of log entries)
    log_entries = db.Column(db.JSON, default=list)
    
    # Result summary
    error_message = db.Column(db.Text)
    
    # Relationships
    host = db.relationship('Host', backref=db.backref('scan_requests', lazy='dynamic',
                                                       order_by='desc(ScanRequest.created_at)'))
    requester = db.relationship('User', backref=db.backref('scan_requests', lazy='dynamic'))
    
    # Indexes
    __table_args__ = (
        db.Index('idx_scan_request_status', 'host_id', 'status'),
    )
    
    def add_log(self, message: str, level: str = 'info'):
        """Add a log entry."""
        if self.log_entries is None:
            self.log_entries = []
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': message
        }
        # Must reassign to trigger SQLAlchemy change detection
        self.log_entries = self.log_entries + [entry]
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'log_entries': self.log_entries or [],
            'error_message': self.error_message,
        }
    
    def __repr__(self):
        return f'<ScanRequest {self.id} for Host {self.host_id} [{self.status}]>'


class TamperAlert(db.Model):
    """Tamper/integrity alerts from daemon."""
    
    __tablename__ = 'tamper_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    
    # Alert details
    alert_type = db.Column(db.String(50), nullable=False)  # file_deleted, file_modified, daemon_stopping, uninstall_attempt
    details = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='critical')  # critical, high, medium
    
    # Status
    is_acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    acknowledged_at = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    host = db.relationship('Host', backref=db.backref('tamper_alerts', lazy='dynamic',
                                                       order_by='desc(TamperAlert.created_at)'))
    
    # Indexes
    __table_args__ = (
        db.Index('idx_tamper_host', 'host_id', 'is_acknowledged'),
        db.Index('idx_tamper_type', 'alert_type'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'alert_type': self.alert_type,
            'details': self.details,
            'severity': self.severity,
            'is_acknowledged': self.is_acknowledged,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
    
    def __repr__(self):
        return f'<TamperAlert {self.alert_type} for Host {self.host_id}>'


class HookBypass(db.Model):
    """Record of a developer using --no-verify to bypass pre-commit hooks."""

    __tablename__ = 'hook_bypasses'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    commit_hash = db.Column(db.String(40))
    commit_message = db.Column(db.String(500))
    commit_author = db.Column(db.String(200))
    repo_path = db.Column(db.String(500))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_acknowledged = db.Column(db.Boolean, default=False)

    host = db.relationship('Host', backref=db.backref('hook_bypasses', lazy='dynamic'))

    __table_args__ = (
        db.Index('idx_hook_bypass_host', 'host_id', 'is_acknowledged'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'commit_hash': self.commit_hash,
            'commit_message': self.commit_message,
            'commit_author': self.commit_author,
            'repo_path': self.repo_path,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'is_acknowledged': self.is_acknowledged,
        }

    def __repr__(self):
        return f'<HookBypass {self.commit_hash[:8] if self.commit_hash else "?"} for Host {self.host_id}>'


class AIToolInfo(db.Model):
    """AI tool detection information from hosts."""

    __tablename__ = 'ai_tool_info'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    scan_report_id = db.Column(db.Integer, db.ForeignKey('scan_reports.id'), nullable=False)

    tool_name = db.Column(db.String(100), nullable=False)  # "Claude Code", "Cursor", "OpenClaw"
    version = db.Column(db.String(100))
    is_running = db.Column(db.Boolean, default=False)
    config_path = db.Column(db.String(500))

    # JSON fields for complex nested data
    mcp_servers = db.Column(db.JSON)    # List of MCP server dicts
    open_ports = db.Column(db.JSON)     # List of open port dicts
    redacted_secrets = db.Column(db.JSON)  # List of redacted secret dicts

    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)

    host = db.relationship('Host', backref=db.backref('ai_tools', lazy='dynamic'))

    __table_args__ = (
        db.Index('idx_aitool_host', 'host_id', 'tool_name'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'tool_name': self.tool_name,
            'version': self.version,
            'is_running': self.is_running,
            'config_path': self.config_path,
            'mcp_servers': self.mcp_servers or [],
            'open_ports': self.open_ports or [],
            'redacted_secrets': self.redacted_secrets or [],
            'first_seen_at': self.first_seen_at.isoformat() if self.first_seen_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
        }

    def __repr__(self):
        return f'<AIToolInfo {self.tool_name} on Host {self.host_id}>'


class Vulnerability(db.Model):
    """Known vulnerability associated with a package on a host."""

    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    package_info_id = db.Column(db.Integer, db.ForeignKey('package_info.id'), nullable=True)

    # Denormalised package details (kept even if PackageInfo row is deleted on rescan)
    package_name = db.Column(db.String(200), nullable=False)
    package_version = db.Column(db.String(100))
    package_manager = db.Column(db.String(50), nullable=False)
    ecosystem = db.Column(db.String(50), nullable=False)

    # Vulnerability details
    vuln_id = db.Column(db.String(100), nullable=False)  # e.g. CVE-2021-44228, GHSA-xxx
    summary = db.Column(db.Text)
    severity_label = db.Column(db.String(20))  # critical, high, medium, low
    cvss_score = db.Column(db.Float, nullable=True)
    affected_versions = db.Column(db.Text)
    fixed_version = db.Column(db.String(100), nullable=True)

    # Extra metadata
    references = db.Column(db.JSON)  # list of URL strings
    source = db.Column(db.String(50), default='osv.dev')

    # Lifecycle
    first_detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)

    # Relationships
    host = db.relationship('Host', backref=db.backref('vulnerabilities', lazy='dynamic'))
    package_info = db.relationship('PackageInfo', backref=db.backref('vulnerabilities', lazy='dynamic'))

    # Indexes
    __table_args__ = (
        db.Index('idx_vuln_host_resolved', 'host_id', 'is_resolved'),
        db.Index('idx_vuln_id', 'vuln_id'),
        db.Index('idx_vuln_package', 'package_name', 'package_manager'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'package_info_id': self.package_info_id,
            'package_name': self.package_name,
            'package_version': self.package_version,
            'package_manager': self.package_manager,
            'ecosystem': self.ecosystem,
            'vuln_id': self.vuln_id,
            'summary': self.summary,
            'severity_label': self.severity_label,
            'cvss_score': self.cvss_score,
            'affected_versions': self.affected_versions,
            'fixed_version': self.fixed_version,
            'references': self.references,
            'source': self.source,
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'is_resolved': self.is_resolved,
        }

    def __repr__(self):
        return f'<Vulnerability {self.vuln_id} for {self.package_name}@{self.package_version}>'


class WebhookSubscription(db.Model):
    """Outbound webhook endpoint registered by a customer.

    The HMAC secret is stored in plaintext because the portal needs it to
    sign every outgoing delivery; the receiver needs the same plaintext to
    verify. Show it once in the UI on creation and only on explicit reveal
    after that.
    """

    __tablename__ = 'webhook_subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    customer_key_id = db.Column(db.Integer, db.ForeignKey('customer_keys.id'), nullable=False, index=True)

    name = db.Column(db.String(100), nullable=False)
    # For slack/generic this is the endpoint URL; for pagerduty it's the
    # Events API v2 routing (integration) key.
    url = db.Column(db.String(500), nullable=False)

    # Delivery type — drives payload formatting in the delivery worker.
    TYPE_GENERIC = 'generic'
    TYPE_SLACK = 'slack'
    TYPE_PAGERDUTY = 'pagerduty'
    VALID_TYPES = (TYPE_GENERIC, TYPE_SLACK, TYPE_PAGERDUTY)
    type = db.Column(db.String(20), nullable=False, default=TYPE_GENERIC)

    # JSON array of event-type strings; ["*"] subscribes to all.
    event_types = db.Column(db.JSON, nullable=False)

    # Plaintext HMAC secret, format "whsec_<43 base64url chars>".
    secret = db.Column(db.String(64), nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Health tracking — drives auto-disable after CONSECUTIVE_FAILURE_LIMIT.
    consecutive_failures = db.Column(db.Integer, default=0, nullable=False)
    last_success_at = db.Column(db.DateTime, nullable=True)
    last_failure_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    customer_key = db.relationship(
        'CustomerKey',
        backref=db.backref('webhook_subscriptions', lazy='dynamic'),
    )
    creator = db.relationship('User')

    CONSECUTIVE_FAILURE_LIMIT = 25  # auto-deactivate after this many

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.public_id:
            self.public_id = str(uuid.uuid4())
        if not self.secret:
            self.secret = self.generate_secret()

    @staticmethod
    def generate_secret():
        """Return a fresh secret like ``whsec_<43-char base64url>``."""
        import base64
        import secrets
        raw = secrets.token_bytes(32)
        return 'whsec_' + base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

    def matches_event(self, event_type: str) -> bool:
        if not self.is_active:
            return False
        types = self.event_types or []
        return '*' in types or event_type in types

    def record_success(self):
        self.consecutive_failures = 0
        self.last_success_at = datetime.utcnow()

    def record_failure(self):
        self.consecutive_failures = (self.consecutive_failures or 0) + 1
        self.last_failure_at = datetime.utcnow()
        if self.consecutive_failures >= self.CONSECUTIVE_FAILURE_LIMIT:
            self.is_active = False

    def to_dict(self, *, reveal_secret: bool = False):
        return {
            'id': self.public_id,
            'name': self.name,
            'url': self.url,
            'type': self.type or 'generic',
            'event_types': self.event_types or [],
            'secret': self.secret if reveal_secret else None,
            'is_active': self.is_active,
            'consecutive_failures': self.consecutive_failures,
            'last_success_at': self.last_success_at.isoformat() if self.last_success_at else None,
            'last_failure_at': self.last_failure_at.isoformat() if self.last_failure_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<WebhookSubscription {self.public_id} -> {self.url}>'


class WebhookDelivery(db.Model):
    """One delivery attempt of one event to one subscription.

    Persisted before the first attempt and updated in place across retries.
    Keeping every attempt's outcome (status, response_code, error) lets us
    expose a deliveries timeline in the portal and replay failures.
    """

    __tablename__ = 'webhook_deliveries'

    # status values: pending, succeeded, failed, retrying
    STATUS_PENDING = 'pending'
    STATUS_RETRYING = 'retrying'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(
        db.Integer,
        db.ForeignKey('webhook_subscriptions.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )

    event_id = db.Column(db.String(36), nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    payload = db.Column(db.JSON, nullable=False)

    status = db.Column(db.String(20), default=STATUS_PENDING, nullable=False)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)

    last_attempt_at = db.Column(db.DateTime, nullable=True)
    response_code = db.Column(db.Integer, nullable=True)
    response_body = db.Column(db.Text, nullable=True)
    last_error = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    subscription = db.relationship(
        'WebhookSubscription',
        backref=db.backref(
            'deliveries',
            lazy='dynamic',
            cascade='all, delete-orphan',
            order_by='desc(WebhookDelivery.created_at)',
        ),
    )

    __table_args__ = (
        db.Index('idx_delivery_sub_status', 'subscription_id', 'status'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'event_type': self.event_type,
            'status': self.status,
            'attempt_count': self.attempt_count,
            'last_attempt_at': self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            'response_code': self.response_code,
            'last_error': self.last_error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self):
        return f'<WebhookDelivery {self.id} {self.event_type} [{self.status}]>'


class ExtensionPolicy(db.Model):
    """Per-customer rule matching extensions and assigning an action.

    Matching: each match_* field is optional; populated criteria are ANDed.
    Glob fields use fnmatch (so ``ms-*`` matches ``ms-python``). risk_level
    is treated as a minimum threshold (``low`` <= ``medium`` <= ``high`` <=
    ``critical``).

    Resolution: policies are evaluated in priority order (lower = first)
    and the first match wins per extension. Putting an ``allow`` policy
    above a broader ``block-alert`` whitelists specific extensions.
    """

    __tablename__ = 'extension_policies'

    ACTION_ALLOW = 'allow'
    ACTION_WARN = 'warn'
    ACTION_BLOCK_ALERT = 'block-alert'
    # Enforced action: alert AND create a quarantine EnforcementAction the
    # daemon executes on the endpoint (opt-in; daemon also has a kill-switch).
    ACTION_QUARANTINE = 'quarantine'
    VALID_ACTIONS = (ACTION_ALLOW, ACTION_WARN, ACTION_BLOCK_ALERT, ACTION_QUARANTINE)

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    customer_key_id = db.Column(db.Integer, db.ForeignKey('customer_keys.id'), nullable=False, index=True)

    name = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=100)
    action = db.Column(db.String(20), nullable=False)

    match_publisher = db.Column(db.String(200), nullable=True)
    match_extension_id = db.Column(db.String(200), nullable=True)
    match_permission_glob = db.Column(db.String(200), nullable=True)
    match_risk_level = db.Column(db.String(20), nullable=True)  # min threshold

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    customer_key = db.relationship(
        'CustomerKey',
        backref=db.backref('extension_policies', lazy='dynamic'),
    )
    creator = db.relationship('User')

    __table_args__ = (
        db.Index('idx_policy_customer_active', 'customer_key_id', 'is_active'),
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.public_id:
            self.public_id = str(uuid.uuid4())

    def to_dict(self):
        return {
            'id': self.public_id,
            'name': self.name,
            'priority': self.priority,
            'action': self.action,
            'match_publisher': self.match_publisher,
            'match_extension_id': self.match_extension_id,
            'match_permission_glob': self.match_permission_glob,
            'match_risk_level': self.match_risk_level,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<ExtensionPolicy {self.name} [{self.action}]>'


class PolicyViolation(db.Model):
    """One (host, policy, extension, extension_version) match.

    Upserted on rescan: re-detecting the same violation refreshes
    last_seen_at instead of inserting a duplicate row. Resolved by admin
    or auto-cleared when the offending extension goes away.
    """

    __tablename__ = 'policy_violations'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('extension_policies.id'), nullable=False)

    extension_id = db.Column(db.String(200), nullable=False)
    extension_name = db.Column(db.String(200), nullable=True)
    extension_version = db.Column(db.String(50), nullable=True)
    publisher = db.Column(db.String(200), nullable=True)
    risk_level = db.Column(db.String(20), nullable=True)
    action_taken = db.Column(db.String(20), nullable=False)  # snapshot of policy.action at detection

    first_detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_resolved = db.Column(db.Boolean, default=False, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    host = db.relationship('Host', backref=db.backref('policy_violations', lazy='dynamic'))
    policy = db.relationship('ExtensionPolicy', backref=db.backref('violations', lazy='dynamic'))
    resolver = db.relationship('User')

    __table_args__ = (
        db.Index('idx_violation_host_resolved', 'host_id', 'is_resolved'),
        db.Index('idx_violation_policy', 'policy_id'),
        db.UniqueConstraint(
            'host_id', 'policy_id', 'extension_id', 'extension_version',
            name='uq_policy_violation_per_ext_version',
        ),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'policy_id': self.policy_id,
            'extension_id': self.extension_id,
            'extension_name': self.extension_name,
            'extension_version': self.extension_version,
            'publisher': self.publisher,
            'risk_level': self.risk_level,
            'action_taken': self.action_taken,
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }

    def __repr__(self):
        return f'<PolicyViolation host={self.host_id} ext={self.extension_id}@{self.extension_version}>'


class ExtensionMetadata(db.Model):
    """Cached marketplace metadata for one (marketplace, extension_id, version).

    Populated by the enrichment worker. The whole point is to detect the
    moment an extension becomes ``is_unpublished`` — that's the
    "removed 3 days ago and you still have it on 14 hosts" demo. The
    transition (False -> True) emits ``extension.unpublished_detected``
    exactly once; subsequent rechecks just refresh ``fetched_at``.
    """

    __tablename__ = 'extension_metadata'

    id = db.Column(db.Integer, primary_key=True)
    marketplace = db.Column(db.String(50), nullable=False)
    extension_id = db.Column(db.String(200), nullable=False)
    version = db.Column(db.String(50), nullable=False)

    publisher_display_name = db.Column(db.String(200), nullable=True)
    install_count = db.Column(db.BigInteger, nullable=True)
    average_rating = db.Column(db.Float, nullable=True)
    last_updated_at = db.Column(db.DateTime, nullable=True)  # marketplace's lastUpdated, not ours

    is_unpublished = db.Column(db.Boolean, default=False, nullable=False)
    unpublished_detected_at = db.Column(db.DateTime, nullable=True)

    raw_data = db.Column(db.JSON, nullable=True)

    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_fetch_status = db.Column(db.Integer, nullable=True)  # http status or None

    __table_args__ = (
        db.UniqueConstraint('marketplace', 'extension_id', 'version', name='uq_ext_meta'),
        db.Index('idx_ext_meta_lookup', 'marketplace', 'extension_id', 'version'),
        db.Index('idx_ext_meta_unpublished', 'is_unpublished'),
        db.Index('idx_ext_meta_fetched_at', 'fetched_at'),
    )

    @property
    def is_stale(self) -> bool:
        from datetime import timedelta
        if self.fetched_at is None:
            return True
        return datetime.utcnow() - self.fetched_at > timedelta(hours=24)

    def to_dict(self):
        return {
            'marketplace': self.marketplace,
            'extension_id': self.extension_id,
            'version': self.version,
            'publisher_display_name': self.publisher_display_name,
            'install_count': self.install_count,
            'average_rating': self.average_rating,
            'last_updated_at': self.last_updated_at.isoformat() if self.last_updated_at else None,
            'is_unpublished': self.is_unpublished,
            'unpublished_detected_at': self.unpublished_detected_at.isoformat() if self.unpublished_detected_at else None,
            'fetched_at': self.fetched_at.isoformat() if self.fetched_at else None,
        }

    def __repr__(self):
        flag = ' UNPUBLISHED' if self.is_unpublished else ''
        return f'<ExtensionMetadata {self.marketplace}:{self.extension_id}@{self.version}{flag}>'


class EnforcementAction(db.Model):
    """A request for the daemon to act on an extension on one host.

    Created either by a ``quarantine`` policy match (``created_by_user_id``
    NULL) or manually by an admin. The daemon polls pending actions for its
    host, executes them (v1: quarantine = move the extension dir aside;
    restore = move it back), and reports the outcome. Reversible by design —
    nothing is deleted.
    """

    __tablename__ = 'enforcement_actions'

    ACTION_QUARANTINE = 'quarantine'
    ACTION_RESTORE = 'restore'
    VALID_ACTIONS = (ACTION_QUARANTINE, ACTION_RESTORE)

    STATUS_PENDING = 'pending'
    STATUS_DISPATCHED = 'dispatched'
    STATUS_APPLIED = 'applied'
    STATUS_FAILED = 'failed'
    STATUS_REVERTED = 'reverted'
    OPEN_STATUSES = (STATUS_PENDING, STATUS_DISPATCHED, STATUS_APPLIED)

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    violation_id = db.Column(db.Integer, db.ForeignKey('policy_violations.id'), nullable=True)

    action = db.Column(db.String(20), nullable=False, default=ACTION_QUARANTINE)
    status = db.Column(db.String(20), nullable=False, default=STATUS_PENDING)

    # Target extension (denormalised so the daemon can resolve it locally).
    extension_id = db.Column(db.String(200), nullable=False)
    extension_name = db.Column(db.String(200), nullable=True)
    extension_version = db.Column(db.String(50), nullable=True)
    ide_type = db.Column(db.String(50), nullable=True)  # e.g. 'vscode', 'cursor', 'intellij-idea'

    # Outcome reported by the daemon.
    original_path = db.Column(db.String(1000), nullable=True)
    quarantine_path = db.Column(db.String(1000), nullable=True)
    result_detail = db.Column(db.Text, nullable=True)

    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # NULL = policy-driven
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    dispatched_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    host = db.relationship('Host', backref=db.backref('enforcement_actions', lazy='dynamic',
                                                       order_by='desc(EnforcementAction.created_at)'))
    violation = db.relationship('PolicyViolation')
    creator = db.relationship('User')

    __table_args__ = (
        db.Index('idx_enforcement_host_status', 'host_id', 'status'),
        db.Index('idx_enforcement_violation', 'violation_id'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'violation_id': self.violation_id,
            'action': self.action,
            'status': self.status,
            'extension_id': self.extension_id,
            'extension_name': self.extension_name,
            'extension_version': self.extension_version,
            'ide_type': self.ide_type,
            'original_path': self.original_path,
            'quarantine_path': self.quarantine_path,
            'result_detail': self.result_detail,
            'created_by_user_id': self.created_by_user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'dispatched_at': self.dispatched_at.isoformat() if self.dispatched_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self):
        return f'<EnforcementAction {self.id} {self.action} {self.extension_id} [{self.status}]>'


class ExtensionPrevalence(db.Model):
    """Per-tenant fleet prevalence of an extension, for drift/anomaly detection
    (Phase 1 B7).

    One row per (customer_key, extension_id). A scheduled sweep recomputes how
    many of the tenant's hosts currently have each extension and compares it to
    the previous sweep's count, so the server can spot fleet-level signals that
    no single host's events reveal: an extension propagating across many hosts
    in a short window (worm-like), or a brand-new high-risk extension appearing.
    """

    __tablename__ = 'extension_prevalence'

    id = db.Column(db.Integer, primary_key=True)
    customer_key_id = db.Column(db.Integer, db.ForeignKey('customer_keys.id'), nullable=False)
    extension_id = db.Column(db.String(200), nullable=False)
    host_count = db.Column(db.Integer, default=0, nullable=False)
    prev_host_count = db.Column(db.Integer, default=0, nullable=False)
    max_risk_level = db.Column(db.String(20))  # highest risk seen across hosts
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('customer_key_id', 'extension_id', name='uq_prevalence_key_ext'),
        db.Index('idx_prevalence_key', 'customer_key_id'),
    )

    def __repr__(self):
        return f'<ExtensionPrevalence {self.extension_id} count={self.host_count}>'
