# 🧪 FTPme Testing Workflow Guide

## 📋 **Testing Strategy Overview**

### **Test Pyramid**
```
    🔺 E2E Tests (5 tests) - Slow, High Value
   🔺🔺 Integration Tests (15 tests) - Medium Speed  
  🔺🔺🔺 Unit Tests (42 tests) - Fast, Low-Level
```

## ⚡ **Development Workflow**

### **1. During Active Development**

#### **Instant Feedback Loop** ⚡
```bash
# Run specific test while developing
pytest tests/unit/test_invitation_system.py::TestInvitationSystem::test_invite_external_user -v

# Run all unit tests (fast - ~1 second)
./run_tests.sh unit

# Run tests with file watching (auto-rerun on changes)
pytest-watch tests/unit/
```

#### **Feature Development Cycle** 🔄
1. **Write failing test first** (TDD approach)
2. **Implement minimum code** to pass test
3. **Run unit tests** (`./run_tests.sh unit`)
4. **Refactor and repeat**

### **2. Before Committing Code**

#### **Pre-Commit Checklist** ✅
```bash
# Full pre-commit validation
./.githooks/pre-commit

# Or run manually:
./run_tests.sh unit        # ~1 second
./run_tests.sh integration # ~2 seconds
python -m py_compile *.py  # Syntax check
```

### **3. Before Pushing to Remote**

#### **Pre-Push Validation** 🚀
```bash
# Run all tests including E2E
./run_tests.sh all         # ~3 seconds

# Generate coverage report
./run_tests.sh coverage    # View in htmlcov/index.html
```

### **4. CI/CD Pipeline** 🤖

#### **Automated Testing Stages**
```yaml
# .github/workflows/test.yml
stages:
  - Unit Tests (parallel, fast feedback)
  - Integration Tests (API validation)
  - E2E Tests (full workflow validation)
  - Coverage Report (quality gate)
```

## 🎯 **When to Run Which Tests**

### **Every Code Change** (1-2 seconds)
```bash
./run_tests.sh unit
```
- **42 unit tests**
- Validates core business logic
- Immediate feedback on breaking changes

### **Every Feature Completion** (3-4 seconds)
```bash
./run_tests.sh integration
```
- **15 integration tests**
- Validates Flask routes and APIs
- Ensures components work together

### **Every Pull Request** (5-6 seconds)
```bash
./run_tests.sh all
```
- **62 total tests**
- Full system validation
- E2E user workflow verification

### **Weekly/Release** (with coverage)
```bash
./run_tests.sh coverage
```
- Quality assessment
- Coverage gap identification
- Performance baseline

## 🚀 **Feature Development Best Practices**

### **1. Test-Driven Development (TDD)**

#### **Red-Green-Refactor Cycle**
```bash
# 1. RED: Write failing test
pytest tests/unit/test_new_feature.py -v  # Should fail

# 2. GREEN: Implement minimum code
# Write just enough code to pass

# 3. REFACTOR: Improve code quality
./run_tests.sh unit  # Ensure still passing
```

### **2. Testing New Features**

#### **For Business Logic Changes**
1. **Start with unit tests** - Test core logic in isolation
2. **Add integration tests** - Test API endpoints
3. **Add E2E tests** - Test complete user workflows (if major feature)

#### **For Bug Fixes**
1. **Write test that reproduces bug** (should fail)
2. **Fix the bug** (test should pass)
3. **Run full test suite** to ensure no regressions

### **3. Continuous Integration Setup**

#### **GitHub Actions Workflow**
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run unit tests
        run: ./run_tests.sh unit
      - name: Run integration tests  
        run: ./run_tests.sh integration
      - name: Run E2E tests
        run: ./run_tests.sh e2e
```

## 📊 **Performance Guidelines**

### **Test Execution Times**
- **Unit Tests**: < 2 seconds (42 tests)
- **Integration Tests**: < 3 seconds (15 tests)
- **E2E Tests**: < 2 seconds (5 tests)
- **Full Suite**: < 5 seconds (62 tests)

### **Coverage Targets**
- **Business Logic**: > 70% (✅ Currently 75%)
- **Critical Paths**: > 90% (invitation system)
- **Overall**: > 30% (✅ Currently 31%)

## 🔧 **Development Environment Setup**

### **IDE Integration**

#### **VS Code Settings**
```json
{
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.pytestArgs": ["tests/"],
    "python.testing.autoTestDiscoverOnSaveEnabled": true
}
```

#### **PyCharm Settings**
- Enable pytest as default test runner
- Set up file watchers for auto-testing
- Configure coverage highlighting

### **Git Hooks Setup**
```bash
# Enable pre-commit hooks
git config core.hooksPath .githooks

# Test the hook
./.githooks/pre-commit
```

## 🎯 **Testing Anti-Patterns to Avoid**

### **❌ Don't Do This**
- Skip tests for "simple" changes
- Only run E2E tests (too slow)
- Test implementation details instead of behavior
- Write tests after code is "done"
- Ignore failing tests

### **✅ Do This Instead**
- Write tests first (TDD)
- Run appropriate test level for change scope
- Test behavior and contracts
- Keep tests fast and focused
- Fix failing tests immediately

## 📈 **Monitoring Test Health**

### **Weekly Review Checklist**
- [ ] All tests passing
- [ ] Coverage maintaining > 70% for business logic
- [ ] Test execution time < 5 seconds for full suite
- [ ] No skipped or ignored tests
- [ ] E2E tests covering critical user paths

### **Quality Gates**
- **No commits** with failing tests
- **No deploys** without full test suite passing
- **Coverage regression** requires justification
- **New features** require corresponding tests

## 🚀 **Quick Reference Commands**

```bash
# Development workflow
./run_tests.sh unit                    # Fast feedback (1s)
./run_tests.sh integration            # API validation (2s)  
./run_tests.sh e2e                    # User workflows (2s)
./run_tests.sh all                    # Full validation (3s)
./run_tests.sh coverage               # Quality check (3s)

# Specific test execution
pytest tests/unit/test_invitation_system.py -v
pytest tests/integration/ -k "test_login"
pytest tests/e2e/ --tb=short

# Pre-commit validation
./.githooks/pre-commit               # Automated gate

# Coverage analysis
open htmlcov/index.html              # View detailed coverage
```

This testing workflow ensures **fast feedback**, **high confidence**, and **maintainable code quality** for your FTPme platform! 🎉 