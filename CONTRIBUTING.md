# Contributing to S3 Security Scanner

Thank you for your interest in contributing to the S3 Security Scanner! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- AWS CLI configured with appropriate credentials
- Good understanding of AWS S3 security concepts

### Development Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/TocConsulting/s3-security-scanner.git
   cd s3-security-scanner
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   # Install all development dependencies from pyproject.toml
   pip install -e ".[dev]"
   
   # Or install manually if needed
   pip install pytest pytest-cov black flake8 mypy "moto[s3]"
   ```

## Development Workflow

### Code Style and Standards

We maintain high code quality standards using the following tools:

#### Code Formatting
```bash
# Format code with Black
black s3_security_scanner/
```

#### Code Linting
```bash
# Check code style with flake8
flake8 s3_security_scanner/

# Type checking with mypy
mypy s3_security_scanner/
```

#### Testing
```bash
# Run tests with pytest
pytest tests/

# Run tests with coverage
pytest --cov=s3_security_scanner tests/
```

### Code Quality Requirements

- **Line Length**: Maximum 79 characters (PEP8 standard)
- **Type Hints**: Required for all public functions and methods
- **Docstrings**: Required for all modules, classes, and public functions
- **Error Handling**: Proper exception handling with logging
- **Security**: No hardcoded credentials or sensitive information

## Making Changes

### Branch Naming Convention

- `feature/description-of-feature` - New features
- `bugfix/description-of-bug` - Bug fixes
- `docs/description-of-changes` - Documentation updates
- `refactor/description-of-refactor` - Code refactoring

### Commit Message Format

```
type(scope): short description

Longer description if needed

- List any breaking changes
- Reference issues: Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, well-documented code
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run all checks
   black s3_security_scanner/
   flake8 s3_security_scanner/
   pytest tests/
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(scanner): add new security check for bucket notifications"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit Pull Request**
   - Provide clear description of changes
   - Reference any related issues
   - Include test results if applicable

## Testing Guidelines

### Test Structure

```
tests/
├── __init__.py
├── test_cli.py                 # CLI option tests
├── test_compliance.py          # Compliance framework tests
├── test_scanner.py             # Scanner functionality tests
├── test_cloudtrail_logging.py  # CloudTrail logging tests
├── test_gdpr_compliance.py     # GDPR compliance tests
└── test_soc2_monitoring.py     # SOC 2 monitoring tests
```

### Writing Tests

- Test individual functions and methods
- Use `unittest` (Python standard library) or `pytest`
- Mock AWS S3 services using `moto[s3]` library (only S3, not all AWS services)
- Use `@mock_aws` decorator (moto 4.x+) for mocking AWS services
- Aim for good test coverage

### Example Test

```python
import unittest
from moto import mock_aws
import boto3
from s3_security_scanner.scanner import S3SecurityScanner

class TestS3Scanner(unittest.TestCase):
    @mock_aws
    def test_check_public_access_block(self):
        """Test public access block configuration check."""
        # Create mock S3 resource
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='test-bucket')
        
        scanner = S3SecurityScanner()
        # Test implementation here
```

## Architecture Guidelines

### Project Structure

```
s3_security_scanner/
├── __init__.py         # Package initialization
├── cli.py              # Command-line interface
├── scanner.py          # Main scanning logic
├── compliance.py       # Compliance framework checks
├── html_reporter.py    # HTML report generation
├── utils.py            # Utility functions
└── templates/          # HTML templates
```

### Adding New Features

#### New Security Checks

1. Add the check method to `S3SecurityScanner` class
2. Update the `scan_bucket` method to include the new check
3. Add issue analysis in `_analyze_issues` method
4. Update compliance frameworks if applicable
5. Add tests for the new functionality

#### New Compliance Frameworks

1. Add framework definition to `ComplianceChecker._define_frameworks`
2. Add remediation steps to `get_remediation_steps`
3. Update HTML templates if needed
4. Add framework to CLI help text

#### New Report Formats

1. Create new reporter class (follow `HTMLReporter` pattern)
2. Add export method to `S3SecurityScanner`
3. Update CLI options
4. Add templates if needed

## Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Python version, AWS region
- **Steps to Reproduce**: Clear steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Error Messages**: Full error messages and stack traces
- **Configuration**: Sanitized configuration details

## Feature Requests

When requesting features, please include:

- **Use Case**: Why this feature would be useful
- **Proposed Solution**: How you envision the feature working
- **Alternatives**: Alternative approaches you've considered
- **Compatibility**: Impact on existing functionality

## Documentation

### Documentation Types

- **Code Documentation**: Inline comments and docstrings
- **User Documentation**: README and usage guides
- **Developer Documentation**: Architecture and contribution guides

### Documentation Standards

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## Security Considerations

### Reporting Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please email security issues to: contact@tocconsulting.fr

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Guidelines

- Never commit AWS credentials or other secrets
- Use environment variables for sensitive configuration
- Follow AWS security best practices
- Validate all user inputs
- Use secure coding practices


## Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check README and inline documentation first

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Release Process

1. **Version Bumping**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Release Notes**: Document new features and fixes in GitHub release notes
3. **Testing**: Run full test suite and manual testing
4. **Documentation**: Update documentation as needed
5. **Release**: Create GitHub release with release notes
6. **Distribution**: Publish to PyPI

Thank you for contributing to making AWS S3 environments more secure!
