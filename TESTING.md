# FTPme Testing Strategy

## 📋 Overview

This document outlines the comprehensive testing strategy for the FTPme secure file exchange platform. We use a multi-layer testing approach to ensure reliability, security, and functionality across all components.

## 🧪 Testing Architecture

### Test Types

1. **Unit Tests** (`tests/unit/`)
   - Test individual functions and classes in isolation
   - Focus on business logic, data validation, and edge cases
   - Fast execution, no external dependencies
   - Target: 90%+ coverage

2. **Integration Tests** (`tests/integration/`)
   - Test Flask routes and API endpoints
   - Test AWS service interactions (mocked)
   - Test database operations
   - Target: 80%+ coverage

3. **End-to-End Tests** (`tests/e2e/`)
   - Test complete user workflows
   - Test cross-system interactions
   - Simulate real user scenarios
   - Target: Key user journeys covered

## 🚀 Quick Start

### Installation
```bash
# Install testing dependencies
pip install -r requirements.txt

# Verify installation
pytest --version
```

### Running Tests
```bash
# Run all tests
pytest

# Run by test type
pytest tests/unit/           # Unit tests only
pytest tests/integration/    # Integration tests only
pytest tests/e2e/           # End-to-end tests only

# Run with coverage
pytest --cov=app --cov=invitation_system

# Run specific test file
pytest tests/unit/test_invitation_system.py

# Run with markers
pytest -m unit              # Only unit tests
pytest -m "not slow"        # Skip slow tests
```

## 📊 Test Coverage

### Current Coverage Targets
- **Overall**: 75% minimum
- **Core Business Logic**: 90%+
- **Critical Security Functions**: 95%+
- **API Endpoints**: 80%+

### Coverage Reports
```bash
# Generate HTML coverage report
pytest --cov=app --cov=invitation_system --cov-report=html

# View report
open htmlcov/index.html
```

## 🔧 Test Configuration

### Environment Variables
Tests use the following environment variables:
```bash
AWS_ACCESS_KEY_ID=testing
AWS_SECRET_ACCESS_KEY=testing  
AWS_DEFAULT_REGION=us-east-2
FLASK_ENV=testing
MOCK_EMAIL=True
```

### Fixtures
Key fixtures available in `tests/conftest.py`:
- `flask_app`: Configured Flask test app
- `client`: Flask test client
- `mock_dynamodb_table`: Mocked DynamoDB tables
- `mock_s3_bucket`: Mocked S3 bucket
- `mock_ses`: Mocked SES service
- `invitation_system`: Configured InvitationSystem
- `sample_*_data`: Test data fixtures

## 📝 Test Organization

### Unit Tests
```
tests/unit/
├── test_invitation_system.py     # InvitationSystem class tests
├── test_user_management.py       # User management logic
├── test_file_operations.py       # File handling functions
└── test_utilities.py             # Helper functions
```

**Key Unit Test Areas:**
- External user invitation workflow
- Internal user management
- Permission validation
- Email template generation
- Data validation and sanitization

### Integration Tests
```
tests/integration/
├── test_flask_routes.py          # API endpoint tests
├── test_database_operations.py   # DynamoDB integration
├── test_s3_operations.py         # S3 file operations
└── test_authentication.py        # Login/logout flows
```

**Key Integration Test Areas:**
- Flask route responses
- Authentication flows
- API error handling
- Database CRUD operations
- File upload/download

### End-to-End Tests
```
tests/e2e/
├── test_user_workflows.py        # Complete user journeys
├── test_invitation_flows.py      # Full invitation process
└── test_file_sharing_workflows.py # File sharing scenarios
```

**Key E2E Test Scenarios:**
- Complete external user invitation and acceptance
- Internal user drop creation and management
- File access permissions across user types
- Organization signup workflow

## 🎯 Testing Best Practices

### Writing Tests
1. **Use descriptive test names** that explain the scenario
2. **Follow AAA pattern**: Arrange, Act, Assert
3. **Test edge cases** and error conditions
4. **Mock external dependencies** (AWS services, email)
5. **Keep tests isolated** and independent

### Example Test Structure
```python
def test_invite_external_user_success(self, invitation_system, mock_dynamodb_table):
    """Test successful external user invitation"""
    # Arrange
    tenant_id = str(uuid.uuid4())
    invitation_data = {
        'email': 'external@partner.com',
        'company_name': 'Partner Company',
        'permissions': ['read', 'download']
    }
    
    # Act
    with patch.object(invitation_system, '_send_email') as mock_send:
        invitation_id = invitation_system.invite_external_user(**invitation_data)
    
    # Assert
    assert invitation_id is not None
    mock_send.assert_called_once()
    # Verify database state...
```

### Mocking Strategy
- **AWS Services**: Use `moto` library for realistic mocking
- **Email**: Mock in development, use test email in staging
- **External APIs**: Mock responses for consistent testing
- **Time-dependent functions**: Use `freezegun` for deterministic tests

## 🚨 Security Testing

### Security Test Areas
1. **Authentication bypass attempts**
2. **Permission escalation scenarios** 
3. **Input validation and sanitization**
4. **Session management security**
5. **External user access boundaries**

### Example Security Tests
```python
def test_external_user_cannot_access_other_tenant_data(self):
    """Ensure external users cannot access other tenant's data"""
    # Test implementation...

def test_invitation_token_expiration(self):
    """Verify expired invitations are rejected"""
    # Test implementation...
```

## 📈 Continuous Integration

### GitHub Actions
Tests run automatically on:
- Every push to main/develop branches
- All pull requests
- Multiple Python versions (3.11, 3.12)

### Pipeline Stages
1. **Lint**: Code formatting and style checks
2. **Unit Tests**: Fast, isolated tests
3. **Integration Tests**: API and service integration
4. **E2E Tests**: Complete workflow validation
5. **Coverage Report**: Code coverage analysis

### Quality Gates
- All tests must pass
- Code coverage ≥75%
- No linting errors
- Security scan passes

## 🐛 Debugging Tests

### Common Issues
1. **Mocking Problems**: Ensure proper patch targets
2. **Fixture Conflicts**: Check fixture dependencies
3. **Environment Variables**: Verify test environment setup
4. **Async Operations**: Handle timing in tests

### Debug Commands
```bash
# Run with verbose output
pytest -v -s

# Run single test with debugging
pytest tests/unit/test_invitation_system.py::TestInvitationSystem::test_invite_external_user -v -s

# Debug with PDB
pytest --pdb

# Show fixture usage
pytest --fixtures
```

## 📋 Test Checklist

### Before Merging Code
- [ ] All tests pass locally
- [ ] New features have corresponding tests
- [ ] Edge cases are covered
- [ ] Security implications tested
- [ ] Documentation updated
- [ ] Code coverage maintained

### Test Review Checklist
- [ ] Test names are descriptive
- [ ] Tests are independent
- [ ] Mocking is appropriate
- [ ] Assertions are meaningful
- [ ] Error cases are tested

## 🔄 Test Data Management

### Sample Data
Test fixtures provide realistic sample data:
- Tenant configurations
- User profiles (internal/external)
- Drop configurations
- File metadata
- Invitation records

### Data Cleanup
- Tests use isolated database instances
- Fixtures handle setup and teardown
- No persistent test data between runs

## 📚 Further Reading

- [pytest Documentation](https://docs.pytest.org/)
- [Flask Testing Guide](https://flask.palletsprojects.com/en/2.3.x/testing/)
- [moto AWS Mocking](https://docs.getmoto.org/)
- [pytest-flask Plugin](https://pytest-flask.readthedocs.io/)

---

**Next Steps:**
1. Run the test suite: `pytest`
2. Review coverage report: `pytest --cov-report=html`
3. Add tests for new features
4. Monitor CI/CD pipeline results 