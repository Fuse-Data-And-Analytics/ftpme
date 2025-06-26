#!/usr/bin/env python3
"""
Add sample drops to the database for testing.
Run this script to populate the database with sample drop data.
"""

import boto3
import os
from datetime import datetime

def add_sample_drops(tenant_id):
    """Add sample drops to the database"""
    
    # Initialize DynamoDB client
    dynamodb = boto3.client('dynamodb')
    
    sample_drops = [
        {
            'id': 'investors',
            'name': 'Investors',
            'purpose': 'Share financial reports and updates with our investors',
            'color': 'blue',
            'internal_users': ['admin', 'cfo'],
            'external_users': ['investor1@example.com', 'analyst@vc.com']
        },
        {
            'id': 'board-meeting',
            'name': 'Q1 Board Meeting',
            'purpose': 'Materials and documents for quarterly board meeting',
            'color': 'green',
            'internal_users': ['admin', 'ceo', 'cfo'],
            'external_users': ['board1@example.com', 'board2@example.com']
        },
        {
            'id': 'marketing-campaign',
            'name': 'Marketing Campaign',
            'purpose': 'Collaborate on Q2 marketing materials and campaigns',
            'color': 'purple',
            'internal_users': ['admin', 'marketing_director'],
            'external_users': ['agency@creative.com', 'freelancer@design.com']
        }
    ]
    
    table_name = os.environ.get('TENANT_TABLE_NAME')
    if not table_name:
        print("Error: TENANT_TABLE_NAME environment variable not set")
        return False
    
    try:
        for drop_data in sample_drops:
            print(f"Adding drop: {drop_data['name']}")
            
            # Convert lists to DynamoDB format
            internal_users_list = [{'S': user} for user in drop_data['internal_users']]
            external_users_list = [{'S': user} for user in drop_data['external_users']]
            
            dynamodb.put_item(
                TableName=table_name,
                Item={
                    'tenant_id': {'S': tenant_id},
                    'user_id': {'S': f"DROP#{drop_data['id']}"},
                    'drop_name': {'S': drop_data['name']},
                    'drop_purpose': {'S': drop_data['purpose']},
                    'drop_color': {'S': drop_data['color']},
                    'created_at': {'S': datetime.now().isoformat()},
                    'created_by': {'S': 'admin'},
                    'internal_users': {'L': internal_users_list},
                    'external_users': {'L': external_users_list}
                }
            )
            
            # Create drop folder in S3 if bucket exists
            bucket_name = os.environ.get('S3_BUCKET_NAME')
            if bucket_name:
                try:
                    s3_client = boto3.client('s3')
                    s3_client.put_object(
                        Bucket=bucket_name,
                        Key=f"{tenant_id}/drops/{drop_data['id']}/.keep",
                        Body=b''
                    )
                    print(f"Created S3 folder for drop: {drop_data['name']}")
                except Exception as e:
                    print(f"Warning: Could not create S3 folder for {drop_data['name']}: {e}")
            
        print(f"Successfully added {len(sample_drops)} sample drops to the database.")
        return True
        
    except Exception as e:
        print(f"Error adding sample drops: {e}")
        return False

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python add_sample_drops.py <tenant_id>")
        print("Example: python add_sample_drops.py tenant-123")
        sys.exit(1)
    
    tenant_id = sys.argv[1]
    
    # Check if required environment variables are set
    required_vars = ['TENANT_TABLE_NAME']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {missing_vars}")
        print("Make sure to source your environment configuration first.")
        sys.exit(1)
    
    print(f"Adding sample drops for tenant: {tenant_id}")
    success = add_sample_drops(tenant_id)
    
    if success:
        print("\n✅ Sample drops added successfully!")
        print("You can now test the live data functionality in the dashboard.")
    else:
        print("\n❌ Failed to add sample drops.")
        sys.exit(1) 