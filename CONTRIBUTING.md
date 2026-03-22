# Contributing to VulnHunter

Thank you for your interest in contributing! This document covers how to add new
modules, run tests, and submit changes.

---

## Development Setup

```bash
git clone https://github.com/vulnhunter/vulnhunter.git
cd vulnhunter
pip install -e ".[dev]"
```

This installs VulnHunter in editable mode plus all dev dependencies
(`pytest`, `pytest-cov`, `pyyaml`).

---

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov --cov-report=term-missing

# Run a specific test file
pytest tests/test_module_sqli.py -v

# Run tests matching a keyword
pytest -k "sqli" -v
```

---

## Adding a New Module

1. **Create the module file** at `modules/yourmodule.py`

2. **Inherit from `BaseModule`** and implement the three required methods:

```python
from modules.base import BaseModule

class YourModule(BaseModule):

    def load_payloads(self) -> list:
        """Return list of payload strings."""
        ...

    def execute(self) -> list:
        """Run the scan and return list of result dicts."""
        ...

    def analyze_response(self, response, payload, param, **kwargs) -> dict:
        """Analyze a single response and return a result dict."""
        ...
```

Each result dict must contain at minimum:
```python
{
    "payload":         str,    # the injected payload
    "param":           str,    # the parameter injected into
    "vulnerable":      bool,   # True if confirmed vulnerable
    "evidence":        str,    # human-readable reason
    "url":             str,    # the injected URL
    "status_code":     int,
    "response_length": int,
}
```

3. **Register the module** in `core/module_loader.py`:

```python
MODULE_REGISTRY = {
    ...
    "yourmodule": ("modules.yourmodule", "YourModuleClass"),
}
```

4. **Add it to the CLI choices** in `main.py`:

```python
target.add_argument("--module", choices=list_modules(), ...)
```

5. **Write tests** in `tests/test_modules.py` covering at minimum:
   - `load_payloads()` returns non-empty list
   - `analyze_response()` correctly flags a known-vulnerable response
   - `analyze_response()` does not flag a clean response

---

## Code Style

- Follow PEP 8
- Use type hints on all function signatures
- Write docstrings for all classes and public methods
- Keep modules self-contained — no cross-module imports

---

## Ethical Guidelines

All contributions must:
- Target only intentionally vulnerable applications (DVWA, vulnweb, HackTheBox, etc.)
- Include no real-world illegal usage examples
- Include appropriate educational comments explaining detection technique

---

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-new-module`
3. Make changes and add tests
4. Verify all tests pass: `pytest`
5. Submit a pull request with a clear description
