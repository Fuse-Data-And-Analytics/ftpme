import boto3
import json
import time
import os
import uuid
from typing import List, Dict, Optional

class UserManager:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.dynamodb = boto3.client('dynamodb')
        self.transfer = boto3.client('transfer')
        self.iam = boto3.client('iam')
        self.s3 = boto3.client('s3')
        
        # Get configuration from environment variables
        self.bucket_name = os.environ.get('S3_BUCKET_NAME')
        self.transfer_server_id = os.environ['TRANSFER_SERVER_ID']
        self.tenant_table = os.environ['TENANT_TABLE_NAME']
        
    def create_user(self, 
                   username: str,
                   email: str,
                   ssh_key: str,
                   role: str = "user") -> Dict[str, str]:
        """Create a new user with per-user IAM role and logical home directory."""
        
        # Create unique IAM role for this user
        role_name = f"ftpme-{self.tenant_id}-{username}-role"
        
        # Create IAM role with tenant-specific permissions
        user_role_arn = self._create_user_iam_role(role_name, username)
        
        # Create logical home directory mapping
        home_directory_mappings = self._create_home_directory_mappings(username)
        
        # Create SFTP user with logical home directory
        self.transfer.create_user(
            ServerId=self.transfer_server_id,
            UserName=f"{self.tenant_id}-{username}",  # Prefix with tenant ID for uniqueness
            Role=user_role_arn,
            SshPublicKeyBody=ssh_key,
            HomeDirectoryType="LOGICAL",
            HomeDirectoryMappings=home_directory_mappings,
            Tags=[
                {
                    'Key': 'TenantId',
                    'Value': self.tenant_id
                },
                {
                    'Key': 'UserRole',
                    'Value': role
                },
                {
                    'Key': 'CreatedBy',
                    'Value': 'ftpme-platform'
                }
            ]
        )
        
        # Ensure tenant directory exists in S3
        self._ensure_tenant_directory_exists()
        
        # Create user metadata in DynamoDB
        user_item = {
            "tenant_id": {"S": self.tenant_id},
            "user_id": {"S": username},
            "sftp_username": {"S": f"{self.tenant_id}-{username}"},
            "email": {"S": email},
            "role": {"S": role},
            "iam_role_arn": {"S": user_role_arn},
            "home_directory_type": {"S": "LOGICAL"},
            "created_at": {"S": time.strftime("%Y-%m-%d %H:%M:%S")},
            "status": {"S": "active"}
        }
        
        self.dynamodb.put_item(
            TableName=self.tenant_table,
            Item=user_item
        )
        
        return {
            "username": username,
            "sftp_username": f"{self.tenant_id}-{username}",
            "tenant_id": self.tenant_id,
            "role": role,
            "iam_role_arn": user_role_arn,
            "home_directory_type": "LOGICAL"
        }
    
    def _create_user_iam_role(self, role_name: str, username: str) -> str:
        """Create IAM role with tenant-specific S3 permissions and KMS access."""
        
        # Trust policy for Transfer Family
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "transfer.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # Get KMS key ID from S3 bucket encryption
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=self.bucket_name)
            kms_key_id = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
        except Exception as e:
            print(f"Warning: Could not get KMS key ID: {e}")
            kms_key_id = None
        
        # IAM policy with tenant-specific S3 access and KMS permissions
        policy_statements = [
            {
                "Sid": "ListBucketInHomeDirectory",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{self.bucket_name}",
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            f"{self.tenant_id}/*",
                            f"{self.tenant_id}"
                        ]
                    }
                }
            },
            {
                "Sid": "AllowUserToAccessOnlyTheirTenantFiles",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion",
                    "s3:DeleteObjectVersion"
                ],
                "Resource": f"arn:aws:s3:::{self.bucket_name}/{self.tenant_id}/*"
            }
        ]
        
        # Add KMS permissions if bucket is encrypted
        if kms_key_id:
            policy_statements.append({
                "Sid": "AllowKMSAccess",
                "Effect": "Allow",
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": kms_key_id
            })
        
        s3_policy = {
            "Version": "2012-10-17",
            "Statement": policy_statements
        }
        
        try:
            # Create IAM role
            create_role_response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"SFTP role for user {username} in tenant {self.tenant_id}",
                Tags=[
                    {
                        'Key': 'Service',
                        'Value': 'ftpme-platform'
                    },
                    {
                        'Key': 'TenantId',
                        'Value': self.tenant_id
                    },
                    {
                        'Key': 'Username',
                        'Value': username
                    }
                ]
            )
            
            # Attach inline policy
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f"{role_name}-s3-policy",
                PolicyDocument=json.dumps(s3_policy)
            )
            
            # If KMS key exists, also add the role to the KMS key policy
            if kms_key_id:
                try:
                    self._add_role_to_kms_key_policy(kms_key_id, create_role_response['Role']['Arn'])
                except Exception as e:
                    print(f"Warning: Could not add role to KMS key policy: {e}")
            
            return create_role_response['Role']['Arn']
            
        except self.iam.exceptions.EntityAlreadyExistsException:
            # Role already exists, get its ARN
            response = self.iam.get_role(RoleName=role_name)
            return response['Role']['Arn']
    
    def _add_role_to_kms_key_policy(self, kms_key_id: str, role_arn: str):
        """Add the Transfer Family role to the KMS key policy."""
        kms = boto3.client('kms')
        
        try:
            # Get current key policy
            key_policy_response = kms.get_key_policy(
                KeyId=kms_key_id,
                PolicyName='default'
            )
            current_policy = json.loads(key_policy_response['Policy'])
            
            # Check if role already has permissions
            role_has_permissions = False
            for statement in current_policy['Statement']:
                if 'Principal' in statement:
                    principals = statement['Principal']
                    if isinstance(principals, dict) and 'AWS' in principals:
                        aws_principals = principals['AWS']
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        if role_arn in aws_principals:
                            role_has_permissions = True
                            break
            
            if not role_has_permissions:
                # Add Transfer Family role to KMS key policy
                new_statement = {
                    "Sid": f"AllowTransferFamilyAccess-{self.tenant_id}",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": role_arn
                    },
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*"
                }
                
                current_policy['Statement'].append(new_statement)
                
                # Update the key policy
                kms.put_key_policy(
                    KeyId=kms_key_id,
                    PolicyName='default',
                    Policy=json.dumps(current_policy)
                )
                
                print(f"✅ Added role {role_arn} to KMS key policy")
            else:
                print(f"✅ Role {role_arn} already has KMS permissions")
                
        except Exception as e:
            print(f"Warning: Could not update KMS key policy: {e}")
            # Don't fail user creation if KMS policy update fails
    
    def _create_home_directory_mappings(self, username: str) -> List[Dict]:
        """Create logical home directory mappings for the user."""
        return [
            {
                'Entry': '/',
                'Target': f'/{self.bucket_name}/{self.tenant_id}'
            }
        ]
    
    def _ensure_tenant_directory_exists(self):
        """Ensure the tenant directory exists in S3."""
        try:
            self.s3.put_object(
                Bucket=self.bucket_name,
                Key=f"{self.tenant_id}/",
                Body=b''
            )
        except Exception as e:
            print(f"Warning: Could not create tenant directory: {e}")
    
    def list_users(self) -> List[Dict[str, str]]:
        """List all users for the tenant."""
        response = self.dynamodb.query(
            TableName=self.tenant_table,
            KeyConditionExpression="tenant_id = :tid",
            ExpressionAttributeValues={
                ":tid": {"S": self.tenant_id}
            }
        )
        
        users = []
        for item in response.get("Items", []):
            # Skip tenant metadata records
            if item.get("user_id", {}).get("S") == "TENANT_METADATA":
                continue
                
            # Only include user records
            if all(key in item for key in ["user_id", "email", "role", "created_at"]):
                users.append({
                    "username": item["user_id"]["S"],
                    "sftp_username": item.get("sftp_username", {}).get("S", f"{self.tenant_id}-{item['user_id']['S']}"),
                    "email": item["email"]["S"],
                    "role": item["role"]["S"],
                    "created_at": item["created_at"]["S"],
                    "status": item.get("status", {}).get("S", "active"),
                    "iam_role_arn": item.get("iam_role_arn", {}).get("S", ""),
                    "home_directory_type": item.get("home_directory_type", {}).get("S", "LOGICAL")
                })
        
        return users
    
    def delete_user(self, username: str) -> None:
        """Delete a user and their associated IAM role."""
        
        # Get user details from DynamoDB first
        response = self.dynamodb.get_item(
            TableName=self.tenant_table,
            Key={
                "tenant_id": {"S": self.tenant_id},
                "user_id": {"S": username}
            }
        )
        
        if 'Item' not in response:
            raise ValueError(f"User {username} not found")
        
        user_item = response['Item']
        sftp_username = user_item.get("sftp_username", {}).get("S", f"{self.tenant_id}-{username}")
        
        # Delete SFTP user
        try:
            self.transfer.delete_user(
                ServerId=self.transfer_server_id,
                UserName=sftp_username
            )
        except self.transfer.exceptions.ResourceNotFoundException:
            print(f"SFTP user {sftp_username} not found, continuing with cleanup")
        
        # Delete IAM role
        role_name = f"ftpme-{self.tenant_id}-{username}-role"
        try:
            # First, delete inline policies
            policies = self.iam.list_role_policies(RoleName=role_name)
            for policy_name in policies['PolicyNames']:
                self.iam.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
            
            # Then delete the role
            self.iam.delete_role(RoleName=role_name)
        except self.iam.exceptions.NoSuchEntityException:
            print(f"IAM role {role_name} not found, continuing with cleanup")
        
        # Delete user metadata from DynamoDB
        self.dynamodb.delete_item(
            TableName=self.tenant_table,
            Key={
                "tenant_id": {"S": self.tenant_id},
                "user_id": {"S": username}
            }
        )

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Manage users for a tenant')
    parser.add_argument('--tenant-id', required=True, help='Tenant ID')
    parser.add_argument('--action', required=True, choices=['create', 'list', 'delete'],
                      help='Action to perform')
    parser.add_argument('--username', help='Username (required for create/delete)')
    parser.add_argument('--email', help='User email (required for create)')
    parser.add_argument('--ssh-key', help='Path to SSH public key file (required for create)')
    parser.add_argument('--role', choices=['admin', 'user'], default='user',
                      help='User role (default: user)')
    
    args = parser.parse_args()
    
    manager = UserManager(args.tenant_id)
    
    if args.action == 'create':
        if not all([args.username, args.email, args.ssh_key]):
            print("Error: --username, --email, and --ssh-key are required for create action")
            return
        
        with open(args.ssh_key, 'r') as f:
            ssh_key = f.read().strip()
        
        result = manager.create_user(
            username=args.username,
            email=args.email,
            ssh_key=ssh_key,
            role=args.role
        )
        
        print("\nUser created successfully!")
        print(f"Username: {result['username']}")
        print(f"Role: {result['role']}")
        print(f"Home Directory: {result['home_directory_type']}")
        print("\nConnection details:")
        print(f"sftp {result['sftp_username']}@{manager.transfer_server_id}.server.transfer.{boto3.Session().region_name}.amazonaws.com")
    
    elif args.action == 'list':
        users = manager.list_users()
        print("\nUsers:")
        for user in users:
            print(f"\nUsername: {user['username']}")
            print(f"Email: {user['email']}")
            print(f"Role: {user['role']}")
            print(f"Created: {user['created_at']}")
    
    elif args.action == 'delete':
        if not args.username:
            print("Error: --username is required for delete action")
            return
        
        manager.delete_user(args.username)
        print(f"\nUser {args.username} deleted successfully!")

if __name__ == "__main__":
    main() 