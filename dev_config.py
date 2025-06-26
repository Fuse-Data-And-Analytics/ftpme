#!/usr/bin/env python3
"""
Development Configuration for FTPme
Set environment variables for testing
"""

import os

def setup_dev_environment():
    """Set up development environment variables"""
    
    # Flask development settings
    os.environ['FLASK_ENV'] = 'development'
    os.environ['DEBUG'] = 'True'
    
    # Email configuration for testing
    # Option 1: Mock emails (just print to console) - RECOMMENDED FOR TESTING
    # os.environ['MOCK_EMAIL'] = 'True'
    
    # Option 2: Use SES with verified email (now that email is verified!)
    os.environ['MOCK_EMAIL'] = 'False'
    os.environ['SES_VERIFIED_EMAIL'] = 'findlay.dave@gmail.com'  # Verified email address
    
    print("🔧 Development environment configured:")
    print(f"   FLASK_ENV: {os.environ.get('FLASK_ENV')}")
    print(f"   DEBUG: {os.environ.get('DEBUG')}")
    print(f"   MOCK_EMAIL: {os.environ.get('MOCK_EMAIL')}")
    if os.environ.get('SES_VERIFIED_EMAIL'):
        print(f"   SES_VERIFIED_EMAIL: {os.environ.get('SES_VERIFIED_EMAIL')}")

if __name__ == "__main__":
    setup_dev_environment() 