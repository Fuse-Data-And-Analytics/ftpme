from aws_cdk import (
    aws_transfer as transfer,
    aws_iam as iam,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    RemovalPolicy,
    CfnOutput,
    Duration
)
from constructs import Construct
import json
from datetime import datetime, timezone

class SftpUserManagement(Construct):
    def __init__(self, scope: Construct, id: str, 
                 transfer_server: transfer.CfnServer,
                 storage_bucket: s3.Bucket,
                 tenant_table: dynamodb.Table,
                 **kwargs):
        super().__init__(scope, id, **kwargs)
        
        self.transfer_server = transfer_server
        self.storage_bucket = storage_bucket
        self.tenant_table = tenant_table

        # Create a base IAM role for SFTP users
        self.user_role = iam.Role(
            self, "SftpUserRole",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            description="Base role for SFTP users"
        )

        # Add S3 permissions
        self.user_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                resources=[
                    storage_bucket.bucket_arn,
                    f"{storage_bucket.bucket_arn}/*"
                ]
            )
        )

    def create_sftp_user(self, username: str, tenant_id: str, ssh_public_key: str, 
                        home_directory: str = None, tags: dict = None):
        """
        Create a new SFTP user with the specified configuration
        
        Args:
            username (str): The username for SFTP access
            tenant_id (str): The tenant identifier
            ssh_public_key (str): The user's SSH public key
            home_directory (str): Optional custom home directory path
            tags (dict): Optional tags to apply to the user
        """
        # Set default home directory if not provided
        if not home_directory:
            home_directory = f"/{self.storage_bucket.bucket_name}/{tenant_id}/{username}"

        # Create user-specific IAM role
        user_specific_role = iam.Role(
            self, f"SftpRole{username}",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            description=f"Role for SFTP user {username}"
        )

        # Add same permissions as base role
        user_specific_role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                self, f"UserPolicy{username}",
                managed_policy_arn=self.user_role.role_arn
            )
        )

        # Prepare user tags
        user_tags = [
            transfer.CfnUser.TagProperty(
                key="Tenant",
                value=tenant_id
            )
        ]
        if tags:
            user_tags.extend([
                transfer.CfnUser.TagProperty(key=k, value=v)
                for k, v in tags.items()
            ])

        # Create the SFTP user
        user = transfer.CfnUser(
            self, f"SftpUser{username}",
            server_id=self.transfer_server.attr_server_id,
            user_name=username,
            role=user_specific_role.role_arn,
            home_directory=home_directory,
            home_directory_type="LOGICAL",
            ssh_public_keys=[ssh_public_key],
            tags=user_tags
        )

        # Store user metadata in DynamoDB
        self.store_user_metadata(
            username=username,
            tenant_id=tenant_id,
            home_directory=home_directory
        )

        return user

    def store_user_metadata(self, username: str, tenant_id: str, home_directory: str):
        """
        Store user metadata in DynamoDB
        """
        # Calculate TTL for 1 year from now
        ttl = int((datetime.now(timezone.utc) + Duration.days(365)).timestamp())

        # Store user metadata
        self.tenant_table.put_item(
            Item={
                'tenant_id': tenant_id,
                'user_id': username,
                'home_directory': home_directory,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'ttl': ttl
            }
        )

    def delete_sftp_user(self, username: str, tenant_id: str):
        """
        Delete an SFTP user and their associated resources
        """
        # Delete the user from Transfer Family
        transfer.CfnUser.from_cfn_user_attributes(
            self, f"DeleteUser{username}",
            server_id=self.transfer_server.attr_server_id,
            user_name=username
        ).apply_removal_policy(RemovalPolicy.DESTROY)

        # Delete user metadata from DynamoDB
        self.tenant_table.delete_item(
            Key={
                'tenant_id': tenant_id,
                'user_id': username
            }
        )

    def update_ssh_key(self, username: str, new_ssh_public_key: str):
        """
        Update the SSH public key for an existing user
        """
        user = transfer.CfnUser.from_cfn_user_attributes(
            self, f"UpdateUser{username}",
            server_id=self.transfer_server.attr_server_id,
            user_name=username
        )
        
        user.add_property_override(
            "SshPublicKeys", [new_ssh_public_key]
        )
