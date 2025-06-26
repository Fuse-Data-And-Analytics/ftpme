#!/usr/bin/env python3
import boto3
import json
from datetime import datetime

def create_drops_table():
    """Create DynamoDB table for storing drops metadata"""
    
    dynamodb = boto3.resource('dynamodb')
    
    # Table schema for drops
    table_name = 'FileExchangeDrops'
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'tenant_id',
                    'KeyType': 'HASH'  # Partition key
                },
                {
                    'AttributeName': 'drop_id',
                    'KeyType': 'RANGE'  # Sort key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'tenant_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'drop_id',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST',
            StreamSpecification={
                'StreamEnabled': True,
                'StreamViewType': 'NEW_AND_OLD_IMAGES'
            },

            SSESpecification={
                'Enabled': True
            },
            Tags=[
                {
                    'Key': 'Environment',
                    'Value': 'Production'
                },
                {
                    'Key': 'Service',
                    'Value': 'FileExchange'
                }
            ]
        )
        
        print(f"Creating table {table_name}...")
        table.wait_until_exists()
        print(f"Table {table_name} created successfully!")
        
        # Add sample drops for testing
        add_sample_drops(table)
        
    except Exception as e:
        print(f"Error creating table: {e}")

def add_sample_drops(table):
    """Add sample drops for testing"""
    
    sample_drops = [
        {
            'tenant_id': 'a02678d0-8ad8-4510-b1a4-92b2701a19f5',
            'drop_id': 'investors',
            'name': 'Investors',
            'purpose': 'Share financial reports and updates with our investors',
            'color': 'blue',
            'created_by': 'admin',
            'created_at': datetime.utcnow().isoformat(),
            'internal_users': ['admin', 'cfo'],
            'external_users': ['investor1@example.com', 'analyst@vc.com'],
            'settings': {
                'sftp_enabled': True,
                'email_notifications': False,
                'version_control': True
            },
            'status': 'active'
        },
        {
            'tenant_id': 'a02678d0-8ad8-4510-b1a4-92b2701a19f5',
            'drop_id': 'board-meeting',
            'name': 'Q1 Board Meeting',
            'purpose': 'Materials and documents for quarterly board meeting',
            'color': 'green',
            'created_by': 'admin',
            'created_at': datetime.utcnow().isoformat(),
            'internal_users': ['admin', 'ceo', 'cfo'],
            'external_users': ['board1@example.com', 'board2@example.com'],
            'settings': {
                'sftp_enabled': True,
                'email_notifications': True,
                'version_control': True
            },
            'status': 'active'
        }
    ]
    
    print("Adding sample drops...")
    for drop in sample_drops:
        table.put_item(Item=drop)
        print(f"Added drop: {drop['name']}")

if __name__ == "__main__":
    create_drops_table() 