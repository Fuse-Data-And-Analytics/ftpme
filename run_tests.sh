#!/bin/bash

# FTPme Test Runner Script
# This script sets up the proper environment and runs tests

# Set testing environment variables
export FLASK_ENV=development
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
export AWS_DEFAULT_REGION=us-east-2
export MOCK_EMAIL=True

echo "🧪 FTPme Test Runner"
echo "==================="

# Check what type of test to run
if [ "$1" = "unit" ]; then
    echo "Running unit tests..."
    pytest tests/unit/ -v
elif [ "$1" = "integration" ]; then
    echo "Running integration tests..."
    pytest tests/integration/ -v
elif [ "$1" = "e2e" ]; then
    echo "Running end-to-end tests..."
    pytest tests/e2e/ -v
elif [ "$1" = "coverage" ]; then
    echo "Running tests with coverage..."
    pytest tests/unit/ --cov=app --cov=invitation_system --cov-report=html --cov-report=term-missing -v
    echo "📊 Coverage report generated in htmlcov/index.html"
elif [ "$1" = "all" ]; then
    echo "Running all tests..."
    pytest -v
else
    echo "Usage: ./run_tests.sh [unit|integration|e2e|coverage|all]"
    echo ""
    echo "Available options:"
    echo "  unit        - Run unit tests only"
    echo "  integration - Run integration tests only" 
    echo "  e2e         - Run end-to-end tests only"
    echo "  coverage    - Run unit tests with coverage report"
    echo "  all         - Run all tests"
    echo ""
    echo "Example: ./run_tests.sh unit"
fi 