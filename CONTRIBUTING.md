# Contributing to BlueSentinel

Thank you for your interest in contributing to BlueSentinel. This document explains how to contribute code, tests, detection rules, and documentation to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Adding Detection Rules](#adding-detection-rules)
- [Security Disclosure](#security-disclosure)

---

## Code of Conduct

Contributors are expected to interact professionally and respectfully. This project is a security tool — contributions that introduce backdoors, deliberately weaken detection logic, or otherwise undermine the platform's integrity will be rejected and reported.

---

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bluesentinel.git
   cd "BlueSentinel V2.0"
   ```
3. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```
4. Make your changes, write tests, and open a pull request against `develop`.

---

## Development Setup

**Requirements:** Python 3.11+, pip

```bash
# Install all dependencies including dev extras
pip install -r requirements.txt
pip install flake8

# Copy environment template
cp .env.example .env
# Populate .env with test API keys (see .env.example for guidance)
```

**Running the test suite:**

```bash
pytest tests/py/ --tb=short -v
```

**Running YARA rule validation:**

```bash
# Requires yara CLI installed
find rules/yara -name "*.yar" | xargs -I{} yara {} /dev/null
```

**Running the dashboard locally:**

```bash
python -m core.orchestrator --dashboard
# Open https://localhost:5000
```

---

## Code Style

### Python

- **Line length:** 120 characters maximum (flake8 configured in CI).
- **Type hints:** All public functions and methods must have type annotations.
- **Docstrings:** All modules, classes, and public methods require docstrings. Use Google style.
- **Error handling:** Catch specific exceptions. Never use bare `except:`. Log errors; do not silently swallow them.
- **Imports:** Standard library first, then third-party, then local. One blank line between each group.
- **No global mutable state** outside of explicitly designated singleton patterns (e.g., `config_manager.py`).

Example:

```python
def calculate_score(self, result: ScanResult) -> int:
    """Calculate a 0–100 threat score for the given scan result.

    Args:
        result: The completed scan result containing alerts and matches.

    Returns:
        Integer score in the range [0, 100].

    Raises:
        ValueError: If result is None.
    """
```

### JavaScript

- ES2020+ syntax.
- `const` / `let` only — no `var`.
- Functions documented with JSDoc comments.
- No external dependencies beyond Chart.js and Socket.IO (already pinned in base.html).

### PowerShell

- `[CmdletBinding()]` on all scripts.
- `Set-StrictMode -Version Latest`.
- `$ErrorActionPreference = 'Stop'` for scripts that must not silently fail.
- Comment-based help (`<# .SYNOPSIS ... #>`) on all scripts and functions.

### HTML / CSS

- Jinja2 template syntax. All templates must extend `base.html`.
- CSS uses design token custom properties defined in `dashboard.css` — do not hardcode colour values.
- No Bootstrap or other CSS frameworks. Grid and Flexbox only.

---

## Testing Requirements

Every code change that touches logic must be accompanied by tests.

### Python — pytest

- Test files live in `tests/py/`.
- File naming: `test_<module>.py`.
- Use fixtures and `monkeypatch` for isolation — no tests may write to production paths.
- Minimum coverage expectations:
  - New analyser modules: cover happy path, edge cases, and error paths.
  - New API client code: cover 200 success, 404 not found, 429 rate limit, and network error.
  - New scoring/detection logic: cover boundary values and cap/floor behaviour.

Run tests:

```bash
pytest tests/py/ --tb=short -v
```

### PowerShell — Pester v5

- Test files live in `tests/ps/`.
- File naming: `*.Tests.ps1`.
- Use `BeforeAll` / `AfterAll` for setup/teardown.
- Use `Set-ItResult -Skipped` when the tested script is unavailable rather than failing.

Run tests (requires Pester v5):

```powershell
Invoke-Pester -Path tests/ps/ -Output Detailed
```

### CI must pass

All pull requests are blocked on CI passing:

- Python unit tests
- YARA rule validation
- Python syntax check
- Sigma rule YAML validation

---

## Pull Request Process

1. **Branch from `develop`**, not `main`. The `main` branch tracks releases only.

2. **Title format:** Use a concise imperative title:
   - `Add AbuseIPDB domain lookup`
   - `Fix beaconing detector jitter calculation`
   - `Update VirusTotal cache TTL for IP lookups`

3. **PR body** must include:
   - What the change does and why.
   - Test scenarios covered.
   - Any configuration changes required.

4. **One logical change per PR.** Refactoring, feature additions, and bug fixes should be separate PRs unless tightly coupled.

5. **Signed commits** are encouraged but not required.

6. A maintainer will review within 5 business days. Address all review comments before requesting re-review.

7. PRs are merged via **squash merge** into `develop` to keep history clean.

---

## Adding Detection Rules

### YARA Rules

- Place new rules in `rules/yara/`.
- Every rule must include `meta:` with at minimum:
  - `author`
  - `description`
  - `severity` (low / medium / high / critical)
  - `mitre_technique` (e.g., `T1059.001`)
- Test rules against known-clean samples to confirm no false positives before submitting.
- Run `yara <rule_file> /dev/null` to confirm syntax is valid.

### Sigma Rules

- Place new rules in `rules/sigma/`.
- Follow the existing file naming convention: `<tactic>.yml` (one file per MITRE tactic).
- Required fields: `title`, `id`, `status`, `description`, `logsource`, `detection`, `falsepositives`, `level`.
- Use `bs-<tactic_abbrev>-<seq>` for rule IDs (e.g., `bs-de-004`).
- Tag all rules with ATT&CK tactic and technique IDs.

---

## Security Disclosure

If you discover a security vulnerability in BlueSentinel itself (e.g., a path traversal in the dashboard, an injection in report generation, or a logic flaw that causes missed detections), please disclose it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Contact the author directly:

- **Author:** Valon Canolli — Cyber Security Engineer
- Describe the vulnerability, reproduction steps, and potential impact.
- Allow reasonable time for a fix before public disclosure.

Security-related contributions (patches, hardening, detection improvements) are warmly welcomed and will be credited in the changelog.

---

*BlueSentinel v2.0 — Valon Canolli*
