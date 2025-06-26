import boto3
import os
from typing import Dict, Optional

def create_user(tenant_id: str, username: str, email: str, ssh_key: str) -> Dict[str, str]:
    """Create a new user for a tenant."""
    # Get configuration from environment variables
    bucket_name = os.environ['S3_BUCKET_NAME']
    transfer_server_id = os.environ['TRANSFER_SERVER_ID']
    transfer_user_role = os.environ['TRANSFER_USER_ROLE']
    tenant_table = "FileExchangePlatformDev-TenantTable6A37AA6C-1DTBC6KGIVLJW"  # Updated table name
    
    # Create SFTP user
    transfer = boto3.client('transfer')
    home_directory = f"/{bucket_name}/{tenant_id}/{username}"
    transfer.create_user(
        ServerId=transfer_server_id,
        UserName=username,
        Role=transfer_user_role,
        SshPublicKeyBody=ssh_key,
        HomeDirectory=home_directory
    )
    
    # Create user metadata
    dynamodb = boto3.client('dynamodb')
    user_item = {
        "tenant_id": {"S": tenant_id},
        "user_id": {"S": username},
        "email": {"S": email},
        "role": {"S": "user"},
        "home_directory": {"S": home_directory}
    }
    
    dynamodb.put_item(
        TableName=tenant_table,
        Item=user_item
    )
    
    return {
        "username": username,
        "home_directory": home_directory
    }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Create an SFTP user')
    parser.add_argument('--username', required=True, help='Username for SFTP access')
    parser.add_argument('--tenant-id', required=True, help='Tenant ID')
    parser.add_argument('--ssh-public-key', required=True, help='Path to SSH public key file')
    
    args = parser.parse_args()
    
    create_user(
        username=args.username,
        tenant_id=args.tenant_id,
        email="",
        ssh_key=open(args.ssh_public_key, 'r').read().strip()
    )
