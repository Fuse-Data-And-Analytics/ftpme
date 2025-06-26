#!/usr/bin/env python3
"""
Development Configuration for FTPme
Set environment variables for testing
"""

import os

class DevelopmentConfig:
    """Development configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'dev-secret-key-for-testing'
    DEBUG = True
    TESTING = False
    
    # Upload settings
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = 'uploads'
    
    # Session settings
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # AWS settings (loaded from environment) - consolidated to us-east-2
    AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-2')
    CLIENT_FILES_BUCKET = os.environ.get('CLIENT_FILES_BUCKET')
    TENANT_TABLE_NAME = os.environ.get('TENANT_TABLE_NAME')
    TRANSFER_SERVER_ID = os.environ.get('TRANSFER_SERVER_ID')
    
    # Email configuration for development
    MOCK_EMAIL = os.environ.get('MOCK_EMAIL', 'False').lower() == 'true'
    SES_VERIFIED_EMAIL = os.environ.get('SES_VERIFIED_EMAIL', 'dev@example.com')

def setup_dev_environment():
    """Set up development environment variables"""
    
    # Flask development settings
    os.environ['FLASK_ENV'] = 'development'
    os.environ['DEBUG'] = 'True'
    
    # Email configuration for testing
    # Option 1: Mock emails (just print to console) - RECOMMENDED FOR TESTING
    # os.environ['MOCK_EMAIL'] = 'True'  # Back to mock emails for testing
    
    # Option 2: Use SES with business email (much better for deliverability!)
    os.environ['MOCK_EMAIL'] = 'False'
    os.environ['SES_VERIFIED_EMAIL'] = 'dave@fusedata.co'  # Business email address
    
    print("🔧 Development environment configured:")
    print(f"   FLASK_ENV: {os.environ.get('FLASK_ENV')}")
    print(f"   DEBUG: {os.environ.get('DEBUG')}")
    print(f"   MOCK_EMAIL: {os.environ.get('MOCK_EMAIL')}")
    if os.environ.get('SES_VERIFIED_EMAIL'):
        print(f"   SES_VERIFIED_EMAIL: {os.environ.get('SES_VERIFIED_EMAIL')}")

if __name__ == "__main__":
    setup_dev_environment() 