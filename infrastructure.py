#!/usr/bin/env python3
import aws_cdk as cdk
from aws_cdk import (
    aws_transfer as transfer,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_logs as logs,
    aws_kms as kms
)

class FileExchangeStack(cdk.Stack):
    def __init__(self, scope: cdk.App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # KMS Key for encryption
        self.encryption_key = kms.Key(
            self, "FileExchangeKey",
            enable_key_rotation=True,
            pending_window=cdk.Duration.days(7),
            removal_policy=cdk.RemovalPolicy.RETAIN,
            alias="ftpme-file-exchange-key"
        )

        # Add comprehensive permissions for CloudWatch Logs to use the KMS key
        self.encryption_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsAccess",
                effect=iam.Effect.ALLOW,
                principals=[
                    iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
                ],
                actions=[
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                    "kms:CreateGrant"
                ],
                resources=["*"],
                conditions={
                    "ArnEquals": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:log-group:*"
                    }
                }
            )
        )

        # Create centralized S3 bucket for all tenant files
        self.client_files_bucket = s3.Bucket(
            self, "ClientFilesBucket",
            versioned=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.encryption_key,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            cors=[
                s3.CorsRule(
                    allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.PUT, s3.HttpMethods.DELETE],
                    allowed_origins=["*"],
                    allowed_headers=["*"]
                )
            ],
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=cdk.Duration.days(90)
                        )
                    ],
                    noncurrent_version_expiration=cdk.Duration.days(90)
                )
            ]
        )

        # Create DynamoDB table for tenant and user metadata
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
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.encryption_key,
            time_to_live_attribute="ttl"
        )

        # CloudWatch Log Group for SFTP logs (created after KMS key policy is set)
        self.log_group = logs.LogGroup(
            self, "FileTransferLogs",
            retention=logs.RetentionDays.ONE_YEAR,
            encryption_key=self.encryption_key,
            removal_policy=cdk.RemovalPolicy.RETAIN
        )

        # Ensure log group depends on the KMS key policy
        self.log_group.node.add_dependency(self.encryption_key)

        # IAM role for Transfer Family server logging
        self.transfer_logging_role = iam.Role(
            self, "TransferLoggingRole",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            description="Role for AWS Transfer Family server logging"
        )

        self.transfer_logging_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[self.log_group.log_group_arn + ":*"]
            )
        )

        # Create single centralized Transfer Family SFTP server
        self.transfer_server = transfer.CfnServer(
            self, "CentralizedTransferServer",
            protocols=["SFTP"],
            domain="S3",
            identity_provider_type="SERVICE_MANAGED",
            endpoint_type="PUBLIC",
            logging_role=self.transfer_logging_role.role_arn,
            protocol_details=transfer.CfnServer.ProtocolDetailsProperty(
                passive_ip="AUTO",
                set_stat_option="ENABLE_NO_OP",
                tls_session_resumption_mode="ENFORCED"
            ),
            security_policy_name="TransferSecurityPolicy-2020-06",
            structured_log_destinations=[
                self.log_group.log_group_arn
            ],
            tags=[
                cdk.CfnTag(key="Environment", value="Production"),
                cdk.CfnTag(key="Service", value="FileExchange"),
                cdk.CfnTag(key="Type", value="Centralized")
            ]
        )

        # Output the centralized server details
        cdk.CfnOutput(self, "TransferServerIdOutput", value=self.transfer_server.attr_server_id)
        cdk.CfnOutput(self, "ClientFilesBucketOutput", value=self.client_files_bucket.bucket_name)
        cdk.CfnOutput(self, "TenantTableOutput", value=self.tenant_table.table_name)
        cdk.CfnOutput(self, "TransferServerEndpointOutput", 
                     value=f"{self.transfer_server.attr_server_id}.server.transfer.{self.region}.amazonaws.com")

    def create_user_role_template(self, tenant_id: str) -> iam.Role:
        """
        Create a template IAM role for SFTP users with tenant-specific permissions
        This method can be called from application code to create per-user roles
        """
        return iam.Role(
            self, f"SftpUserRole-{tenant_id}",
            assumed_by=iam.ServicePrincipal("transfer.amazonaws.com"),
            description=f"Role for SFTP users in tenant {tenant_id}",
            inline_policies={
                "SftpAccess": iam.PolicyDocument(
                    statements=[
                        # Allow listing bucket contents with prefix restriction
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["s3:ListBucket"],
                            resources=[self.client_files_bucket.bucket_arn],
                            conditions={
                                "StringLike": {
                                    "s3:prefix": [f"{tenant_id}/*"]
                                }
                            }
                        ),
                        # Allow object operations within tenant prefix
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject",
                                "s3:DeleteObject",
                                "s3:GetObjectVersion"
                            ],
                            resources=[f"{self.client_files_bucket.bucket_arn}/{tenant_id}/*"]
                        )
                    ]
                )
            }
        )

app = cdk.App()
FileExchangeStack(app, "FileExchangePlatformDev")
app.synth() 