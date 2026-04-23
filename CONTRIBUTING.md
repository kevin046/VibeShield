# Contributing to the Kraken Security Framework

Thanks for your interest in contributing! This document outlines the process.

## Development Setup

```bash
# Fork and clone
git clone git@github.com:kevin046/clawmolt-kraken.git
cd clawmolt-kraken

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v
```

## Code Style

- Python 3.11+ with type hints
- Follow PEP 8 (use `ruff check .` or `flake8`)
- All public functions must have docstrings
- Security-sensitive code must have inline comments explaining the threat model

## Commit Messages

Use conventional commits:

```
type(scope): description

feat(layer1): add seccomp profile support
fix(layer2): correct fingerprint latency threshold
docs: update SECURITY.md with new threat model
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `security`, `chore`

## Security Contributions

If you're fixing a security vulnerability, please report it privately first via
SECURITY.md before opening a PR. We will coordinate disclosure timing.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest tests/ -v`)
5. Update documentation if applicable
6. Open a PR with a clear description

## License

All contributions are under Apache-2.0. By contributing, you agree to license your
changes under this license.
