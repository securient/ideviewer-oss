---
title: Secrets Detection
nav_order: 3
parent: Features
---

# Secrets Detection

IDEViewer scans for plaintext credentials in configuration files and git history, reporting their presence and location without ever transmitting the actual secret values.

## Detected Secret Types

- Ethereum private keys
- BIP-39 mnemonic phrases
- AWS access keys and secret keys
- API tokens (generic patterns)
- Database connection strings with embedded credentials
- Private keys (RSA, SSH)

## CLI Usage

```bash
# Scan for secrets
ideviewer secrets

# Output as JSON
ideviewer secrets --json

# Output as SARIF for CI/CD integration
ideviewer secrets --output-sarif > secrets.sarif

# Scan only staged git files (for pre-commit hooks)
ideviewer secrets --check-staged

# Exit with code 1 if secrets found (for CI/CD)
ideviewer secrets --exit-code
```

## Git History Scanning

IDEViewer scans not just current files but also git history for secrets that may have been committed and later removed. A secret that existed in a previous commit is still a risk -- it lives in the repository's history and can be recovered.

## Privacy

{: .important }
IDEViewer **never transmits actual secret values** to the portal. It reports only:
- The type of secret detected (e.g., "AWS Access Key")
- The file path and line number
- The variable name (e.g., `AWS_SECRET_ACCESS_KEY`)
- A severity rating

No secret value ever leaves the developer's machine.

## Auto-Resolution

When a secret is removed from a file, the next daemon scan detects its absence and marks it as resolved in the portal. This provides a clear audit trail of secret exposure and remediation.

## SARIF Output

The `--output-sarif` flag produces SARIF v2.1.0 output compatible with:

- GitHub Code Scanning
- CodeQL
- Any CI/CD tool that accepts SARIF

```bash
# Example: upload to GitHub Code Scanning
ideviewer secrets --output-sarif > secrets.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -X POST -F sarif=@secrets.sarif
```

## Portal View

In the portal, the **Secrets** tab on the host detail page shows all detected secrets with their type, location, severity, and resolution status.

![Exposed Secrets](../images/Exposed%20Secrets.png)
