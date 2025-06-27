"""
Production Flask Configuration
For enterprise-scale deployment of FTPme platform
"""
import os
from multiprocessing import cpu_count

class ProductionConfig:
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'production-secret-key-change-this'
    DEBUG = False
    TESTING = False
    
    # Upload settings
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = '/tmp/uploads'
    
    # Session settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # AWS settings (loaded from environment) - consolidated to us-east-2
    AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-2')
    CLIENT_FILES_BUCKET = os.environ.get('CLIENT_FILES_BUCKET')
    TENANT_TABLE_NAME = os.environ.get('TENANT_TABLE_NAME')
    TRANSFER_SERVER_ID = os.environ.get('TRANSFER_SERVER_ID')
    SES_VERIFIED_EMAIL = os.environ.get('SES_VERIFIED_EMAIL', 'noreply@ftpme.com')

class GunicornConfig:
    """Gunicorn WSGI server configuration for production"""
    
    # Server socket
    bind = "0.0.0.0:8000"
    backlog = 2048
    
    # Worker processes
    workers = cpu_count() * 2 + 1  # Common formula for CPU-bound apps
    worker_class = "gevent"  # Async workers for I/O-bound operations
    worker_connections = 1000
    max_requests = 1000
    max_requests_jitter = 50
    
    # Restart workers after this many requests (prevents memory leaks)
    timeout = 30
    keepalive = 2
    
    # Logging
    loglevel = "info"
    accesslog = "/var/log/ftpme/access.log"
    errorlog = "/var/log/ftpme/error.log"
    
    # Process naming
    proc_name = "ftpme-flask"
    
    # Performance
    preload_app = True
    
    # Security
    forwarded_allow_ips = '*'  # Configure based on your load balancer

# Example startup command:
# gunicorn --config production_config.py:GunicornConfig app:app 