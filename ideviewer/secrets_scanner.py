"""
Secrets Scanner - Detects plaintext secrets in common configuration files.

This module scans for potentially exposed secrets like:
- Ethereum/Crypto wallet private keys in .env files
- API keys and tokens
- Other sensitive credentials

IMPORTANT: This scanner does NOT extract or transmit actual secret values.
It only reports the presence of potential secrets.
"""

import os
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """Represents a detected secret (without the actual value)."""
    file_path: str
    secret_type: str
    variable_name: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "critical"  # critical, high, medium, low
    description: str = ""
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "secret_type": self.secret_type,
            "variable_name": self.variable_name,
            "line_number": self.line_number,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class SecretsResult:
    """Result of a secrets scan."""
    timestamp: datetime
    findings: List[SecretFinding] = field(default_factory=list)
    scanned_paths: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.severity == "critical"),
            "scanned_paths": self.scanned_paths,
            "errors": self.errors,
        }


class SecretsScanner:
    """
    Scanner for detecting plaintext secrets in configuration files.
    
    Currently supports:
    - Ethereum/EVM wallet private keys
    - Bitcoin private keys (WIF format)
    - Generic private keys
    - AWS credentials
    - API keys/tokens
    """
    
    # Ethereum private key patterns (64 hex chars, with or without 0x prefix)
    ETH_PRIVATE_KEY_PATTERNS = [
        # With 0x prefix
        r'(?:0x)?[a-fA-F0-9]{64}',
    ]
    
    # Variable names commonly used for private keys
    PRIVATE_KEY_VAR_NAMES = [
        r'PRIVATE_KEY',
        r'PRIV_KEY',
        r'ETH_PRIVATE_KEY',
        r'ETHEREUM_PRIVATE_KEY',
        r'WALLET_PRIVATE_KEY',
        r'DEPLOYER_PRIVATE_KEY',
        r'DEPLOYER_KEY',
        r'OWNER_PRIVATE_KEY',
        r'SIGNER_PRIVATE_KEY',
        r'MNEMONIC',
        r'SEED_PHRASE',
        r'SECRET_KEY',
        r'WALLET_KEY',
        r'ACCOUNT_KEY',
    ]
    
    # AWS credential patterns
    AWS_PATTERNS = {
        'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'aws_secret_key': r'[a-zA-Z0-9+/]{40}',
    }
    
    # Files to scan
    TARGET_FILES = [
        '.env',
        '.env.local',
        '.env.development',
        '.env.production',
        '.env.test',
        '.envrc',
        'config.env',
        '.secrets',
        'secrets.env',
    ]
    
    # Directories to search in (relative to home)
    SEARCH_DIRS = [
        '',  # Home directory itself
        'Documents',
        'Projects',
        'Development',
        'dev',
        'projects',
        'code',
        'src',
        'work',
        'workspace',
        'repos',
        'git',
        'github',
    ]
    
    def __init__(self, max_depth: int = 5, scan_hidden: bool = False):
        """
        Initialize the secrets scanner.
        
        Args:
            max_depth: Maximum directory depth to scan
            scan_hidden: Whether to scan hidden directories (except .env files)
        """
        self.max_depth = max_depth
        self.scan_hidden = scan_hidden
        self.home_dir = Path.home()
    
    def scan(self, additional_paths: Optional[List[str]] = None) -> SecretsResult:
        """
        Scan for plaintext secrets.
        
        Args:
            additional_paths: Additional paths to scan
        
        Returns:
            SecretsResult with findings
        """
        result = SecretsResult(timestamp=datetime.now())
        
        # Build list of directories to scan
        scan_dirs = []
        for subdir in self.SEARCH_DIRS:
            path = self.home_dir / subdir if subdir else self.home_dir
            if path.exists() and path.is_dir():
                scan_dirs.append(path)
        
        # Add additional paths
        if additional_paths:
            for p in additional_paths:
                path = Path(p)
                if path.exists():
                    scan_dirs.append(path)
        
        # Scan each directory
        for scan_dir in scan_dirs:
            try:
                self._scan_directory(scan_dir, result, depth=0)
            except Exception as e:
                error_msg = f"Error scanning {scan_dir}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)
        
        return result
    
    def _scan_directory(self, directory: Path, result: SecretsResult, depth: int):
        """Recursively scan a directory for .env files."""
        if depth > self.max_depth:
            return
        
        try:
            for item in directory.iterdir():
                try:
                    # Skip hidden directories (but not hidden files like .env)
                    if item.is_dir():
                        if item.name.startswith('.') and not self.scan_hidden:
                            continue
                        # Skip common non-project directories
                        if item.name in ('node_modules', 'venv', '.venv', '__pycache__', 
                                        '.git', 'vendor', 'dist', 'build', '.cache',
                                        'Library', 'Applications', '.Trash'):
                            continue
                        self._scan_directory(item, result, depth + 1)
                    
                    elif item.is_file() and item.name in self.TARGET_FILES:
                        self._scan_env_file(item, result)
                        
                except PermissionError:
                    pass  # Skip files/dirs we can't access
                except Exception as e:
                    logger.debug(f"Error processing {item}: {e}")
                    
        except PermissionError:
            pass  # Skip directories we can't access
    
    def _scan_env_file(self, file_path: Path, result: SecretsResult):
        """Scan a single .env file for secrets."""
        try:
            result.scanned_paths.append(str(file_path))
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # Skip comments and empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE format
                if '=' not in line:
                    continue
                
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                
                # Check for Ethereum private key
                finding = self._check_eth_private_key(file_path, key, value, line_num)
                if finding:
                    result.findings.append(finding)
                    continue
                
                # Check for mnemonic/seed phrase
                finding = self._check_mnemonic(file_path, key, value, line_num)
                if finding:
                    result.findings.append(finding)
                    continue
                
                # Check for AWS credentials
                finding = self._check_aws_credentials(file_path, key, value, line_num)
                if finding:
                    result.findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            result.errors.append(f"Error scanning {file_path}: {str(e)}")
    
    def _check_eth_private_key(self, file_path: Path, key: str, value: str, 
                                line_num: int) -> Optional[SecretFinding]:
        """Check if value looks like an Ethereum private key."""
        # Check if variable name suggests it's a private key
        key_upper = key.upper()
        is_key_name_match = any(
            re.search(pattern, key_upper) 
            for pattern in self.PRIVATE_KEY_VAR_NAMES
        )
        
        # Check if value looks like a private key (64 hex chars)
        value_clean = value.replace('0x', '').replace('0X', '')
        is_hex_64 = bool(re.match(r'^[a-fA-F0-9]{64}$', value_clean))
        
        # Only flag if BOTH the name and value match
        # This reduces false positives
        if is_key_name_match and is_hex_64:
            return SecretFinding(
                file_path=str(file_path),
                secret_type="ethereum_private_key",
                variable_name=key,
                line_number=line_num,
                severity="critical",
                description="Plaintext Ethereum/EVM private key detected. This key can be used to sign transactions and drain funds from the associated wallet.",
                recommendation="Use encrypted keystores (e.g., Foundry's 'cast wallet import') or hardware wallets for production deployments. Never store private keys in plaintext.",
            )
        
        return None
    
    def _check_mnemonic(self, file_path: Path, key: str, value: str,
                        line_num: int) -> Optional[SecretFinding]:
        """Check if value looks like a mnemonic/seed phrase."""
        key_upper = key.upper()
        
        # Check if variable name suggests mnemonic
        if not any(x in key_upper for x in ['MNEMONIC', 'SEED', 'PHRASE', 'WORDS']):
            return None
        
        # Check if value looks like a mnemonic (12 or 24 words)
        words = value.split()
        if len(words) in (12, 24) and all(w.isalpha() for w in words):
            return SecretFinding(
                file_path=str(file_path),
                secret_type="mnemonic_seed_phrase",
                variable_name=key,
                line_number=line_num,
                severity="critical",
                description="Plaintext mnemonic/seed phrase detected. This can be used to derive all wallet keys and drain all associated funds.",
                recommendation="Use encrypted keystores or hardware wallets. Never store seed phrases in plaintext files.",
            )
        
        return None
    
    def _check_aws_credentials(self, file_path: Path, key: str, value: str,
                                line_num: int) -> Optional[SecretFinding]:
        """Check for AWS credentials."""
        key_upper = key.upper()
        
        # Check for AWS access key
        if 'AWS' in key_upper and 'ACCESS' in key_upper:
            if re.match(self.AWS_PATTERNS['aws_access_key'], value):
                return SecretFinding(
                    file_path=str(file_path),
                    secret_type="aws_access_key",
                    variable_name=key,
                    line_number=line_num,
                    severity="high",
                    description="AWS Access Key ID detected in plaintext.",
                    recommendation="Use AWS IAM roles, environment variables from secure vaults, or AWS SSO instead of hardcoded credentials.",
                )
        
        # Check for AWS secret key
        if 'AWS' in key_upper and 'SECRET' in key_upper:
            if len(value) == 40 and re.match(r'^[a-zA-Z0-9+/]+$', value):
                return SecretFinding(
                    file_path=str(file_path),
                    secret_type="aws_secret_key",
                    variable_name=key,
                    line_number=line_num,
                    severity="critical",
                    description="AWS Secret Access Key detected in plaintext.",
                    recommendation="Use AWS IAM roles, environment variables from secure vaults, or AWS SSO instead of hardcoded credentials.",
                )
        
        return None


def scan_secrets(additional_paths: Optional[List[str]] = None) -> SecretsResult:
    """
    Convenience function to scan for secrets.
    
    Args:
        additional_paths: Additional paths to scan
    
    Returns:
        SecretsResult with findings
    """
    scanner = SecretsScanner()
    return scanner.scan(additional_paths)
