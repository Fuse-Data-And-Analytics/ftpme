from aws_cdk import (
    Stack,
    aws_transfer as transfer,
    aws_s3 as s3,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    aws_logs as logs,
    aws_kms as kms,
    RemovalPolicy,
    Tags,
    Duration,
    CfnOutput
)
from constructs import Construct
from .user_management import SftpUserManagement


class FileExchangePlatform(Stack):
    def __init__(self, scope: Construct, construct_id: str, env_name: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # KMS Key for encryption
        self.encryption_key = kms.Key(
            self, "FileExchangeKey",
            enable_key_rotation=True,
            pending_window=Duration.days(7),
            removal_policy=RemovalPolicy.RETAIN,
            alias=f"{env_name}-file-exchange-key"
        )

        # Add permissions for CloudWatch Logs to use the KMS key
        self.encryption_key.add_to_resource_policy(
            iam.PolicyStatement(
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*"
                ],
                principals=[
                    iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"
                    }
                }
            )
        )

        # Enable server access logging
        self.access_logs_bucket = s3.Bucket(
            self, "AccessLogsBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.encryption_key,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Storage for file exchange with logging configured
        self.storage_bucket = s3.Bucket(
            self, "FileExchangeBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.encryption_key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            server_access_logs_bucket=self.access_logs_bucket,
            server_access_logs_prefix="file-exchange-logs/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(90)
                        )
                    ],
                    noncurrent_version_expiration=Duration.days(90)
                )
            ]
        )

        # Tenant metadata table
        self.tenant_table = dynamodb.Table(
            self, "TenantTable",
            partition_key=dynamodb.Attribute(
                name="tenant_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="user_id",
                type=dynamodb.AttributeType.STRING
            ),
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.encryption_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            removal_policy=RemovalPolicy.RETAIN,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl"
        )

        # CloudWatch Log Group for SFTP logs
        self.log_group = logs.LogGroup(
            self, "FileTransferLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=self.encryption_key,
            removal_policy=RemovalPolicy.RETAIN
        )

        # IAM role for SFTP server
        self.transfer_role = iam.Role(
            self, "TransferRole",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            description="Role for AWS Transfer Family SFTP server"
        )

        self.transfer_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                resources=[
                    self.storage_bucket.bucket_arn,
                    f"{self.storage_bucket.bucket_arn}/*"
                ]
            )
        )

        # SFTP Server
        self.transfer_server = transfer.CfnServer(
            self, "FileTransferServer",
            protocols=["SFTP"],
            domain="S3",
            identity_provider_type="SERVICE_MANAGED",
            logging_role=self.transfer_role.role_arn,
            protocol_details=transfer.CfnServer.ProtocolDetailsProperty(
                passive_ip="AUTO",
                set_stat_option="ENABLE_NO_OP",
                tls_session_resumption_mode="ENFORCED"
            ),
            security_policy_name="TransferSecurityPolicy-2020-06",
            structured_log_destinations=[
                self.log_group.log_group_arn
            ]
        )
        
        # Add user management
        self.user_management = SftpUserManagement(
            self, "UserManagement",
            transfer_server=self.transfer_server,
            storage_bucket=self.storage_bucket,
            tenant_table=self.tenant_table
        )

        # Add tags to all resources
        Tags.of(self).add("Environment", env_name)
        Tags.of(self).add("Service", "FileExchange")
        Tags.of(self).add("ManagedBy", "CDK")

        # Add these outputs at the end of __init__
        CfnOutput(
            self, "TransferServerId",
            value=self.transfer_server.attr_server_id,
            description="SFTP Server ID"
        )

        CfnOutput(
            self, "BucketName",
            value=self.storage_bucket.bucket_name,
            description="S3 Bucket Name"
        )
        
        CfnOutput(
            self, "TransferUserRole",
            value=self.transfer_role.role_arn,
            description="IAM Role ARN for AWS Transfer Family SFTP users"
        )