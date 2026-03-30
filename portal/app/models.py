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
    max_hosts = db.Column(db.Integer, default=5)  # Max hosts allowed for this key (free tier: 5)
    
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
    package_manager = db.Column(db.String(50), nullable=False)  # pip, npm, go, cargo, gem, composer
    install_type = db.Column(db.String(20), default='project')  # global, project
    project_path = db.Column(db.String(500))
    lifecycle_hooks = db.Column(db.JSON)  # npm lifecycle hooks {preinstall: "...", postinstall: "..."}
    
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
    )
    
    def to_dict(self):
        result = {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'package_manager': self.package_manager,
            'install_type': self.install_type,
            'project_path': self.project_path,
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
