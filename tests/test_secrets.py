"""Tests for the secrets scanner patterns and detection."""

import os
import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from ideviewer.secrets_scanner import SecretsScanner, SecretFinding, SecretsResult


class TestSecretFinding:
    """Tests for the SecretFinding dataclass."""

    def test_to_dict(self, sample_secret_finding):
        data = sample_secret_finding.to_dict()
        assert data["file_path"] == "/home/user/project/.env"
        assert data["secret_type"] == "ethereum_private_key"
        assert data["variable_name"] == "PRIVATE_KEY"
        assert data["line_number"] == 3
        assert data["severity"] == "critical"

    def test_defaults(self):
        finding = SecretFinding(file_path="/tmp/.env", secret_type="unknown")
        assert finding.severity == "critical"
        assert finding.variable_name is None
        assert finding.line_number is None


class TestSecretsResult:
    """Tests for SecretsResult."""

    def test_to_dict(self, sample_secrets_result):
        data = sample_secrets_result.to_dict()
        assert data["total_findings"] == 1
        assert data["critical_count"] == 1
        assert len(data["findings"]) == 1
        assert len(data["scanned_paths"]) == 1

    def test_empty_result(self):
        result = SecretsResult(timestamp=datetime.now())
        data = result.to_dict()
        assert data["total_findings"] == 0
        assert data["critical_count"] == 0


class TestEthereumKeyDetection:
    """Tests for Ethereum private key detection patterns."""

    def _scan_env_content(self, content: str) -> SecretsResult:
        """Helper to scan a temporary .env file with given content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(content)
            scanner = SecretsScanner()
            result = SecretsResult(timestamp=datetime.now())
            scanner._scan_env_file(env_file, result)
            return result

    def test_detects_eth_private_key_with_0x(self):
        """Detect 0x-prefixed 64-hex-char private key."""
        content = "PRIVATE_KEY=0x" + "a1" * 32  # 64 hex chars
        result = self._scan_env_content(content)
        assert len(result.findings) == 1
        assert result.findings[0].secret_type == "ethereum_private_key"
        assert result.findings[0].severity == "critical"

    def test_detects_eth_private_key_without_0x(self):
        """Detect bare 64-hex-char private key."""
        content = "ETH_PRIVATE_KEY=" + "ab" * 32
        result = self._scan_env_content(content)
        assert len(result.findings) == 1
        assert result.findings[0].secret_type == "ethereum_private_key"

    def test_detects_deployer_key(self):
        """Detect key named DEPLOYER_PRIVATE_KEY."""
        content = "DEPLOYER_PRIVATE_KEY=" + "ff" * 32
        result = self._scan_env_content(content)
        assert len(result.findings) == 1

    def test_no_false_positive_on_short_hex(self):
        """Short hex values should not trigger detection."""
        content = "PRIVATE_KEY=abcdef1234"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_no_false_positive_on_non_key_name(self):
        """64-hex value with non-key variable name should not trigger."""
        content = "DATABASE_URL=" + "ab" * 32
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_quoted_value(self):
        """Detect private key in quoted value."""
        content = 'PRIVATE_KEY="' + "ab" * 32 + '"'
        result = self._scan_env_content(content)
        assert len(result.findings) == 1

    def test_single_quoted_value(self):
        """Detect private key in single-quoted value."""
        content = "PRIVATE_KEY='" + "ab" * 32 + "'"
        result = self._scan_env_content(content)
        assert len(result.findings) == 1


class TestMnemonicDetection:
    """Tests for mnemonic/seed phrase detection."""

    def _scan_env_content(self, content: str) -> SecretsResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(content)
            scanner = SecretsScanner()
            result = SecretsResult(timestamp=datetime.now())
            scanner._scan_env_file(env_file, result)
            return result

    def test_detects_12_word_mnemonic(self):
        words = " ".join(["abandon"] * 12)
        content = f"MNEMONIC={words}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 1
        assert result.findings[0].secret_type == "mnemonic_seed_phrase"

    def test_detects_24_word_mnemonic(self):
        words = " ".join(["zoo"] * 24)
        content = f"SEED_PHRASE={words}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 1

    def test_no_false_positive_11_words(self):
        """11 words should not be flagged."""
        words = " ".join(["test"] * 11)
        content = f"MNEMONIC={words}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_no_false_positive_non_mnemonic_name(self):
        """12 words with non-mnemonic variable name should not trigger."""
        words = " ".join(["test"] * 12)
        content = f"DESCRIPTION={words}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_mnemonic_with_numbers_ignored(self):
        """Words with numbers are not valid BIP39 words."""
        words = " ".join(["word1"] * 12)
        content = f"MNEMONIC={words}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0


class TestAWSKeyDetection:
    """Tests for AWS credential detection."""

    def _scan_env_content(self, content: str) -> SecretsResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(content)
            scanner = SecretsScanner()
            result = SecretsResult(timestamp=datetime.now())
            scanner._scan_env_file(env_file, result)
            return result

    def test_detects_aws_access_key(self):
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = self._scan_env_content(content)
        assert len(result.findings) == 1
        assert result.findings[0].secret_type == "aws_access_key"
        assert result.findings[0].severity == "high"

    def test_detects_aws_secret_key(self):
        # Exactly 40-char alphanumeric string
        secret = "A" * 40
        content = f"AWS_SECRET_ACCESS_KEY={secret}"
        result = self._scan_env_content(content)
        assert len(result.findings) == 1
        assert result.findings[0].secret_type == "aws_secret_key"
        assert result.findings[0].severity == "critical"

    def test_no_false_positive_short_aws_key(self):
        content = "AWS_ACCESS_KEY_ID=short"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_no_false_positive_non_aws_name(self):
        content = "MY_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0


class TestEnvFileScanning:
    """Tests for .env file discovery and parsing."""

    def _scan_env_content(self, content: str, filename: str = ".env") -> SecretsResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / filename
            env_file.write_text(content)
            scanner = SecretsScanner()
            result = SecretsResult(timestamp=datetime.now())
            scanner._scan_env_file(env_file, result)
            return result

    def test_comments_ignored(self):
        content = "# PRIVATE_KEY=" + "ab" * 32
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_empty_lines_ignored(self):
        content = "\n\n\n"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_lines_without_equals_ignored(self):
        content = "just some text without equals"
        result = self._scan_env_content(content)
        assert len(result.findings) == 0

    def test_scanned_path_recorded(self):
        content = "FOO=bar"
        result = self._scan_env_content(content)
        assert len(result.scanned_paths) == 1

    def test_multiple_findings_in_one_file(self):
        content = (
            "PRIVATE_KEY=" + "ab" * 32 + "\n"
            "MNEMONIC=" + " ".join(["abandon"] * 12) + "\n"
        )
        result = self._scan_env_content(content)
        assert len(result.findings) == 2
