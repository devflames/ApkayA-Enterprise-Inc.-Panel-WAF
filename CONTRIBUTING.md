# Contributing to Apkaya Panel WAF

Thank you for your interest in contributing to Apkaya Panel WAF! We welcome contributions from the community.

**Project Maintainer:** Albert Camings (Full Stack Developer)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors.
Please treat all contributors with respect and professionalism.

## How to Contribute

### Reporting Bugs

Found a bug? Please report it by creating an issue on GitHub:

1. **Check existing issues** - Make sure it hasn't been reported already
2. **Create a new issue** with:
   - Clear, descriptive title
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version, etc.)
   - Error logs or stack traces

### Requesting Features

Have an idea for a new feature?

1. **Check the roadmap** - Ensure it's not already planned
2. **Create a discussion** or issue with:
   - Clear feature description
   - Use cases and benefits
   - Implementation ideas (optional)
   - Examples of how it would be used

### Submitting Code Changes

Want to fix a bug or add a feature? Follow this process:

#### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/your-username/apkaya-panel-waf.git
cd apkaya-panel-waf
```

#### 2. Create a Branch

```bash
# Create a descriptive branch name
git checkout -b fix/issue-123-authentication-bug
# or
git checkout -b feature/website-analytics
```

**Branch naming conventions:**
- `fix/` - Bug fixes
- `feature/` - New features
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `perf/` - Performance improvements
- `test/` - Test additions

#### 3. Make Your Changes

- Follow the code style guidelines (see below)
- Write clear, descriptive commit messages
- Keep commits logical and atomic
- Add tests for new functionality
- Update documentation as needed

#### 4. Test Your Changes

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linter
pylint panel/

# Run type checker
mypy panel/
```

#### 5. Commit and Push

```bash
# Stage your changes
git add .

# Commit with clear message
git commit -m "Fix: Resolve authentication timeout issue

- Increase session timeout from 30 to 60 minutes
- Add session refresh on user activity
- Write unit tests for session management"

# Push to your fork
git push origin fix/issue-123-authentication-bug
```

#### 6. Create Pull Request

1. Go to GitHub and create a pull request
2. Fill in the PR template with:
   - Description of changes
   - Related issue(s)
   - Type of change (bug fix/feature/docs)
   - Testing performed
   - Breaking changes (if any)
3. Wait for review and address any feedback

## Code Style Guidelines

### Python Code Style

We follow PEP 8 with these preferences:

```python
# Good: Clear variable names
user_authentication_timeout = 3600

# Bad: Unclear abbreviations
uat = 3600

# Good: Docstrings for all functions
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user with username and password.
    
    Args:
        username: The user's username
        password: The user's password (will be hashed)
    
    Returns:
        True if authentication successful, False otherwise
    
    Raises:
        ValueError: If username or password is empty
    """
    pass

# Bad: No documentation
def auth(u, p):
    pass

# Good: Type hints
def get_user_by_id(user_id: int) -> Optional[User]:
    pass

# Good: Error handling
try:
    result = database_operation()
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    raise
```

### File Organization

```
panel/
├── modules/           # Core business logic
│   ├── auth.py       # Authentication
│   ├── sites.py      # Website management
│   ├── waf.py        # WAF protection
│   └── ...
├── routes/           # API endpoints (if reorganized)
├── templates/        # HTML templates
├── static/           # CSS, JS, images
├── tests/            # Unit tests
│   ├── test_auth.py
│   ├── test_sites.py
│   └── ...
└── utils.py          # Utility functions
```

### Import Organization

```python
# 1. Standard library
import os
import json
from pathlib import Path

# 2. Third-party packages
from flask import Flask, request
import pymysql

# 3. Local imports
from .modules.auth import auth_manager
from .utils import logger
```

### Naming Conventions

```python
# Constants: UPPER_CASE
MAX_UPLOAD_SIZE = 104857600
DEFAULT_TIMEOUT = 3600

# Classes: PascalCase
class WebServerManager:
    pass

# Functions/methods: snake_case
def create_database(name):
    pass

# Private methods: _leading_underscore
def _internal_helper():
    pass

# Protected methods: _single_leading_underscore
def _protected_method():
    pass
```

## Documentation Guidelines

### Code Comments

```python
# Good: Explains WHY, not WHAT
# We use SHA256 instead of MD5 because it's cryptographically secure
hash_value = hashlib.sha256(password.encode()).hexdigest()

# Bad: Explains WHAT (code is obvious)
# Hash the password
hash_value = hashlib.sha256(password.encode()).hexdigest()
```

### Docstrings

```python
def complex_function(param1: str, param2: int) -> dict:
    """
    Brief one-line summary.
    
    Longer description explaining the function's purpose,
    behavior, and any important notes.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        dict: Description of return value with key/value info
    
    Raises:
        ValueError: When param1 is empty
        TypeError: When param2 is not an integer
    
    Example:
        >>> result = complex_function("test", 42)
        >>> result['status']
        'success'
    
    Note:
        Important implementation details or caveats.
    """
    pass
```

### README Requirements

For new modules:
- Create `MODULE_README.md` documenting:
  - Module purpose
  - Main classes and functions
  - Configuration options
  - Usage examples
  - API endpoints (if applicable)

## Testing Requirements

### Unit Tests

```python
# tests/test_auth.py
import pytest
from panel.modules.auth import auth_manager

class TestAuthentication:
    """Test authentication functionality."""
    
    def test_valid_login(self):
        """Test successful login with correct credentials."""
        result = auth_manager.login("admin", "correct_password")
        assert result['success'] is True
    
    def test_invalid_password(self):
        """Test login failure with incorrect password."""
        result = auth_manager.login("admin", "wrong_password")
        assert result['success'] is False
    
    def test_empty_username(self):
        """Test login with empty username."""
        with pytest.raises(ValueError):
            auth_manager.login("", "password")
```

### Test Coverage

- Aim for 80%+ code coverage
- Test happy paths and error cases
- Mock external dependencies (databases, APIs)
- Use fixtures for common test data

```bash
# Check coverage
pytest --cov=panel tests/
```

## Review Process

1. **Automated Checks**
   - GitHub Actions runs tests
   - Linter checks code style
   - Coverage report generated

2. **Manual Review**
   - Core team reviews code
   - Feedback provided within 48 hours
   - Discussion on design decisions

3. **Approval and Merge**
   - Requires 2 approvals minimum
   - All checks must pass
   - Branch must be up-to-date with main

## Release Process

The core team handles releases:

1. **Version Numbering**: Follow Semantic Versioning (MAJOR.MINOR.PATCH)
2. **Changelog**: Update [CHANGELOG.md](CHANGELOG.md)
3. **Tag**: Create git tag for release
4. **GitHub Release**: Document changes and download links
5. **Announcement**: Post on community channels

## Development Setup

```bash
# Clone and setup
git clone https://github.com/apkaya/apkaya-panel-waf.git
cd apkaya-panel-waf

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Start development server
python run.py --debug
```

## Performance Considerations

When contributing, consider:

- **Database Queries**: Use proper indexing and avoid N+1 queries
- **Caching**: Cache frequently accessed data
- **API Response Times**: Keep response times under 200ms
- **Memory Usage**: Avoid loading entire datasets into memory
- **Background Tasks**: Use async for long-running operations

Example:
```python
# Bad: N+1 query problem
for website in websites:
    stats = get_website_stats(website.id)  # Database query in loop

# Good: Single query with joins
websites = get_websites_with_stats()  # One query
```

## Security Guidelines

When implementing security features:

1. **Input Validation**: Always validate and sanitize user input
2. **Output Encoding**: Encode output for the context (HTML, URL, etc.)
3. **Authentication**: Use secure password hashing (bcrypt, argon2)
4. **Authorization**: Check permissions before allowing actions
5. **Secrets**: Never commit API keys or passwords
6. **Dependencies**: Keep dependencies updated and secure
7. **Logging**: Log security events for auditing

Example:
```python
# Good: Input validation and secure storage
from werkzeug.security import generate_password_hash, check_password_hash

password_hash = generate_password_hash(password, method='pbkdf2:sha256')
is_valid = check_password_hash(password_hash, provided_password)

# Bad: Plaintext password
user.password = password  # NEVER do this
```

## Getting Help

- **Documentation**: Check [docs.apkaya.com](https://docs.apkaya.com)
- **Issues**: Search existing GitHub issues
- **Discussions**: Ask questions in GitHub Discussions
- **Email**: Reach out to dev-team@apkaya.com

## Recognition

Contributors will be:
- Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Credited in release notes
- Added to acknowledgments in README

---

**Thank you for contributing to Apkaya Panel WAF! 🎉**

*Last Updated: January 2026*
