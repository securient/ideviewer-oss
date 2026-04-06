# Contributing to IDEViewer

Thank you for your interest in contributing to IDEViewer! This document provides guidelines for contributing to the project.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/securient/ideviewer-oss.git
   cd ideviewer-oss
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate   # macOS/Linux
   venv\Scripts\activate      # Windows
   ```

3. **Install in development mode:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Set up the portal (optional, for portal development):**
   ```bash
   cd portal
   pip install -r requirements.txt
   flask run
   ```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ideviewer --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py
```

## Code Style

- Follow PEP 8 conventions.
- Use type hints for function signatures.
- Write docstrings for public classes and functions.
- Keep functions focused and under ~50 lines where practical.
- Use `logging` instead of `print()` for debug output.

## Pull Request Guidelines

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Keep PRs focused.** One feature or fix per PR. If you find an unrelated issue, open a separate PR.

3. **Write tests** for new functionality. Bug fixes should include a test that would have caught the bug.

4. **Update documentation** if your change affects user-facing behavior (CLI flags, API endpoints, configuration).

5. **Describe your changes** in the PR description. Explain the "why", not just the "what".

6. **Ensure tests pass** before submitting. CI will run automatically on your PR.

## Issue Reporting

- Use the provided issue templates (Bug Report or Feature Request).
- For bugs, include: steps to reproduce, expected behavior, actual behavior, and your environment (OS, Python version).
- For security vulnerabilities, do NOT open a public issue. Email security@securient.io instead.

## Adding IDE Detectors

To add support for a new IDE:

1. Create a new detector in `ideviewer/detectors/` (see `vscode.py` as a reference).
2. Implement the `detect()` method that returns a list of `IDE` objects.
3. Register the detector in `ideviewer/scanner.py`.
4. Add tests in `tests/`.

## Adding Secret Patterns

To add detection for a new secret type:

1. Add a new pattern in `ideviewer/secrets_scanner.py`.
2. Include `secret_type`, `description`, `severity`, and `recommendation`.
3. Add test cases to verify detection and avoid false positives.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
