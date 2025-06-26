import boto3
import time
import uuid
import os
import json
from typing import Dict, Optional

class TenantManager:
    def __init__(self):
        self.dynamodb = boto3.client('dynamodb')
        self.transfer = boto3.client('transfer')
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')
        
        # Get configuration from environment variables
        self.bucket_name = os.environ.get('S3_BUCKET_NAME')
        self.transfer_server_id = os.environ['TRANSFER_SERVER_ID']
        self.tenant_table = os.environ['TENANT_TABLE_NAME']
        
    def create_tenant(self, 
                     company_name: str, 
                     admin_email: str,
                     admin_username: str,
                     admin_ssh_key: str) -> Dict[str, str]:
        """
        Create a new tenant with an admin user using the centralized architecture.
        Returns a dict with tenant_id and admin credentials.
        """
        # Generate tenant ID
        tenant_id = str(uuid.uuid4())
        
        # Create tenant record in DynamoDB
        tenant_item = {
            "tenant_id": {"S": tenant_id},
            "user_id": {"S": "TENANT_METADATA"},  # Special user_id for tenant records
            "company_name": {"S": company_name},
            "admin_email": {"S": admin_email},
            "admin_username": {"S": admin_username},
            "created_at": {"S": time.strftime("%Y-%m-%d %H:%M:%S")},
            "status": {"S": "active"},
            "storage_quota_gb": {"N": "100"},  # Default quota
            "used_storage_gb": {"N": "0"}
        }
        
        self.dynamodb.put_item(
            TableName=self.tenant_table,
            Item=tenant_item
        )
        
        # Create tenant's root directory in S3
        self._ensure_tenant_directory_exists(tenant_id)
        
        # Create admin user with per-user IAM role
        admin_result = self._create_admin_user(
            tenant_id=tenant_id,
            username=admin_username,
            email=admin_email,
            ssh_key=admin_ssh_key
        )
        
        return {
            "tenant_id": tenant_id,
            "admin_username": admin_username,
            "sftp_username": admin_result["sftp_username"],
            "server_id": self.transfer_server_id,
            "bucket_name": self.bucket_name,
            "iam_role_arn": admin_result["iam_role_arn"]
        }
    
    def _ensure_tenant_directory_exists(self, tenant_id: str):
        """Ensure the tenant directory exists in the centralized S3 bucket."""
        try:
            self.s3.put_object(
                Bucket=self.bucket_name,
                Key=f"{tenant_id}/",
                Body=b'',
                Metadata={
                    'tenant-id': tenant_id,
                    'created-by': 'ftpme-platform'
                }
            )
        except Exception as e:
            print(f"Warning: Could not create tenant directory: {e}")
    
    def _create_admin_user(self, tenant_id: str, username: str, email: str, ssh_key: str) -> Dict[str, str]:
        """Create admin user with per-user IAM role and logical home directory."""
        
        # Create unique IAM role for admin user
        role_name = f"ftpme-{tenant_id}-{username}-admin-role"
        user_role_arn = self._create_admin_iam_role(role_name, tenant_id, username)
        
        # Create logical home directory mapping
        home_directory_mappings = [
            {
                'Entry': '/',
                'Target': f'/{self.bucket_name}/{tenant_id}'
            }
        ]
        
        # Create SFTP admin user with logical home directory
        sftp_username = f"{tenant_id}-{username}"
        self.transfer.create_user(
            ServerId=self.transfer_server_id,
            UserName=sftp_username,
            Role=user_role_arn,
            SshPublicKeyBody=ssh_key,
            HomeDirectoryType="LOGICAL",
            HomeDirectoryMappings=home_directory_mappings,
            Tags=[
                {
                    'Key': 'TenantId',
                    'Value': tenant_id
                },
                {
                    'Key': 'UserRole',
                    'Value': 'admin'
                },
                {
                    'Key': 'CreatedBy',
                    'Value': 'ftpme-platform'
                },
                {
                    'Key': 'CompanyAdmin',
                    'Value': 'true'
                }
            ]
        )
        
        # Create admin user metadata in DynamoDB
        admin_item = {
            "tenant_id": {"S": tenant_id},
            "user_id": {"S": username},
            "sftp_username": {"S": sftp_username},
            "email": {"S": email},
            "role": {"S": "admin"},
            "iam_role_arn": {"S": user_role_arn},
            "home_directory_type": {"S": "LOGICAL"},
            "created_at": {"S": time.strftime("%Y-%m-%d %H:%M:%S")},
            "status": {"S": "active"}
        }
        
        self.dynamodb.put_item(
            TableName=self.tenant_table,
            Item=admin_item
        )
        
        return {
            "sftp_username": sftp_username,
            "iam_role_arn": user_role_arn
        }
    
    def _create_admin_iam_role(self, role_name: str, tenant_id: str, username: str) -> str:
        """Create IAM role with admin-level tenant-specific permissions and KMS access."""
        
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
        
        # IAM policy with full access to tenant's S3 prefix and KMS permissions
        policy_statements = [
            {
                "Sid": "ListBucketInTenantDirectory",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{self.bucket_name}",
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            f"{tenant_id}/*",
                            f"{tenant_id}"
                        ]
                    }
                }
            },
            {
                "Sid": "AllowFullAccessToTenantFiles",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion",
                    "s3:DeleteObjectVersion",
                    "s3:GetObjectAcl",
                    "s3:PutObjectAcl"
                ],
                "Resource": f"arn:aws:s3:::{self.bucket_name}/{tenant_id}/*"
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
                Description=f"SFTP admin role for user {username} in tenant {tenant_id}",
                Tags=[
                    {
                        'Key': 'Service',
                        'Value': 'ftpme-platform'
                    },
                    {
                        'Key': 'TenantId',
                        'Value': tenant_id
                    },
                    {
                        'Key': 'Username',
                        'Value': username
                    },
                    {
                        'Key': 'Role',
                        'Value': 'admin'
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
                    "Sid": f"AllowTransferFamilyAccess-{role_arn.split('/')[-1]}",
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
            # Don't fail tenant creation if KMS policy update fails

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Create a new tenant with admin user')
    parser.add_argument('--company-name', required=True, help='Company name')
    parser.add_argument('--admin-email', required=True, help='Admin user email')
    parser.add_argument('--admin-username', required=True, help='Admin username')
    parser.add_argument('--admin-ssh-key', required=True, help='Path to admin SSH public key file')
    
    args = parser.parse_args()
    
    # Read SSH key
    with open(args.admin_ssh_key, 'r') as f:
        ssh_key = f.read().strip()
    
    # Create tenant
    manager = TenantManager()
    result = manager.create_tenant(
        company_name=args.company_name,
        admin_email=args.admin_email,
        admin_username=args.admin_username,
        admin_ssh_key=ssh_key
    )
    
    print("\nTenant created successfully!")
    print(f"Tenant ID: {result['tenant_id']}")
    print(f"Admin Username: {result['admin_username']}")
    print(f"SFTP Server ID: {result['server_id']}")
    print(f"Home Directory: {result['sftp_username']}")
    print("\nConnection details:")
    print(f"sftp {result['sftp_username']}@{result['server_id']}.server.transfer.{boto3.Session().region_name}.amazonaws.com")

if __name__ == "__main__":
    main() 