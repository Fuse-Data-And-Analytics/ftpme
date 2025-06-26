"""
Pytest configuration and shared fixtures for FTPme tests
"""
import pytest
import os
import tempfile
import uuid
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
from app import app
from invitation_system import InvitationSystem


@pytest.fixture
def flask_app():
    """Create and configure a test Flask app"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['MOCK_EMAIL'] = True
    return app


@pytest.fixture
def client(flask_app):
    """Create a test client"""
    return flask_app.test_client()


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing"""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-2'
    os.environ['TENANT_TABLE_NAME'] = 'FileExchangeTenants'
    os.environ['S3_BUCKET_NAME'] = 'test-ftpme-bucket'


@pytest.fixture
def mock_s3_bucket(mock_aws_credentials):
    """Create a mock S3 bucket for testing"""
    with mock_aws():
        s3 = boto3.client('s3', region_name='us-east-2')
        bucket_name = 'test-ftpme-bucket'
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': 'us-east-2'}
        )
        yield bucket_name


@pytest.fixture
def mock_dynamodb_table(mock_aws_credentials):
    """Create mock DynamoDB tables for testing"""
    with mock_aws():
        dynamodb = boto3.resource('dynamodb', region_name='us-east-2')
        
        # Create FileExchangeTenants table
        tenants_table = dynamodb.create_table(
            TableName='FileExchangeTenants',
            KeySchema=[
                {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                {'AttributeName': 'user_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'tenant_id', 'AttributeType': 'S'},
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Create FileExchangeUsers table
        users_table = dynamodb.create_table(
            TableName='FileExchangeUsers',
            KeySchema=[
                {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                {'AttributeName': 'user_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'tenant_id', 'AttributeType': 'S'},
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Create FileExchangeInvitations table
        invitations_table = dynamodb.create_table(
            TableName='FileExchangeInvitations',
            KeySchema=[
                {'AttributeName': 'invitation_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'invitation_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Create FileExchangeDrops table
        drops_table = dynamodb.create_table(
            TableName='FileExchangeDrops',
            KeySchema=[
                {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                {'AttributeName': 'drop_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'tenant_id', 'AttributeType': 'S'},
                {'AttributeName': 'drop_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        yield {
            'tenants': tenants_table,
            'users': users_table,
            'invitations': invitations_table,
            'drops': drops_table
        }


@pytest.fixture
def mock_ses(mock_aws_credentials):
    """Create mock SES for testing email functionality"""
    with mock_aws():
        ses = boto3.client('ses', region_name='us-east-2')
        # Verify email for testing
        ses.verify_email_identity(EmailAddress='test@example.com')
        yield ses


@pytest.fixture
def sample_tenant_data():
    """Sample tenant data for testing"""
    return {
        'tenant_id': str(uuid.uuid4()),
        'company_name': 'Test Company',
        'admin_email': 'admin@testcompany.com',
        'admin_username': 'testadmin'
    }


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'user_type': 'internal'
    }


@pytest.fixture
def sample_external_user_data():
    """Sample external user data for testing"""
    return {
        'username': 'externaluser',
        'email': 'external@partner.com',
        'user_type': 'external',
        'company_name': 'Partner Company',
        'permissions': ['read', 'download']
    }


@pytest.fixture
def sample_drop_data():
    """Sample drop data for testing"""
    return {
        'drop_id': 'test-drop',
        'name': 'Test Drop',
        'purpose': 'Testing purposes',
        'color': 'blue',
        'created_by': 'testadmin'
    }


@pytest.fixture
def invitation_system(mock_dynamodb_table, mock_ses):
    """Create an invitation system with mocked dependencies"""
    with patch.dict(os.environ, {
        'FLASK_ENV': 'development',
        'MOCK_EMAIL': 'True'
    }):
        return InvitationSystem()


@pytest.fixture
def temp_file():
    """Create a temporary file for testing file operations"""
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
        f.write("Test file content")
        f.flush()
        yield f.name
    os.unlink(f.name) 