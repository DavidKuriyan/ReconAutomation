# Contributing to Aether-Recon

Thank you for your interest in contributing to the Aether-Recon OSINT Framework! We welcome contributions from the community to help make this tool better, safer, and more powerful.

## 🤝 How to Contribute

### 1. Reporting Issues
- **Check existing issues** before reporting a new one.
- **Use the template**: Provide a clear description, reproduction steps, and environment details.
- **Security bugs**: Do NOT post public issues for vulnerabilities. Email us directly (see `SECURITY.md` or contact the maintainer).

### 2. Feature Requests
- Ideas are welcome! Open a "Feature Request" issue.
- Explain the "Why" and "How" of your proposed feature.

### 3. Pull Requests (PRs)
1.  **Fork the repository**.
2.  **Create a branch**: `git checkout -b feature/amazing-feature`.
3.  **Code**: Follow the [Coding Standards](#coding-standards).
4.  **Test**: Ensure your changes functionality works.
5.  **Commit**: Use descriptive commit messages.
6.  **Push**: `git push origin feature/amazing-feature`.
7.  **Open a PR**: Reference any relevant issues.

## 💻 Coding Standards

### Python
- **Version**: Python 3.8+ compatibility is required.
- **Style**: Follow [PEP 8](https://peps.python.org/pep-0008/).
- **Type Hinting**: Use type hints for all function arguments and return values.
- **Docstrings**: All modules, classes, and public functions must have docstrings.
- **Error Handling**: 
    - Wrap external API calls in `try/except` blocks.
    - Handle timeouts and network failures gracefully.
    - Never let a single module crash the entire application.

### Modular Design
- **New Modules**: Place new intelligence modules in `orchestrator/modules/`.
- **Inheritance**: (Future) All modules should inherit from a base `OSINTModule` class.
- **Configuration**: Use `config.py` for all configurable parameters (API keys, timeouts, toggles).

## ⚖️ Ethical Guidelines
- **Consent**: All operational code must respect the `REQUIRE_CONSENT` flag.
- **Privacy**: Do not store PII unnecessarily. Redact sensitive data in logs.
- **Rate Limits**: Respect the rate limits of external APIs. Use the centralized configuration for delays.

## 🧪 Testing
- Run `verify_fix.py` (if applicable) or perform a full scan against a **controlled target** (e.g., your own server) before submitting.

Thank you for building with us! 🚀
