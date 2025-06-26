#!/usr/bin/env python3
"""
FTPme Platform Monitoring Script
Monitors platform health, usage, and generates reports.
"""

import boto3
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List

class FTPmeMonitor:
    def __init__(self):
        self.transfer = boto3.client('transfer')
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.client('dynamodb')
        self.cloudwatch = boto3.client('cloudwatch')
        
        # Get configuration from environment
        self.transfer_server_id = os.environ.get('TRANSFER_SERVER_ID', '')
        self.bucket_name = os.environ.get('S3_BUCKET_NAME', 'ftpme-client-files')
        self.tenant_table = os.environ.get('TENANT_TABLE_NAME', '')
    
    def check_infrastructure_health(self) -> Dict:
        """Check the health of core infrastructure components."""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'components': {}
        }
        
        try:
            # Check Transfer Family server
            transfer_response = self.transfer.describe_server(ServerId=self.transfer_server_id)
            server_state = transfer_response['Server']['State']
            health_status['components']['transfer_server'] = {
                'status': 'healthy' if server_state == 'ONLINE' else 'unhealthy',
                'state': server_state,
                'server_id': self.transfer_server_id
            }
            
            # Check S3 bucket
            self.s3.head_bucket(Bucket=self.bucket_name)
            health_status['components']['s3_bucket'] = {
                'status': 'healthy',
                'bucket_name': self.bucket_name
            }
            
            # Check DynamoDB table
            table_response = self.dynamodb.describe_table(TableName=self.tenant_table)
            table_status = table_response['Table']['TableStatus']
            health_status['components']['dynamodb_table'] = {
                'status': 'healthy' if table_status == 'ACTIVE' else 'unhealthy',
                'table_status': table_status,
                'table_name': self.tenant_table
            }
            
        except Exception as e:
            health_status['overall_status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status
    
    def get_tenant_statistics(self) -> Dict:
        """Get statistics about tenants and users."""
        try:
            response = self.dynamodb.scan(TableName=self.tenant_table)
            items = response.get('Items', [])
            
            tenant_count = 0
            user_count = 0
            admin_count = 0
            
            tenants = set()
            
            for item in items:
                user_id = item.get('user_id', {}).get('S', '')
                
                if user_id == 'TENANT_METADATA':
                    tenant_count += 1
                    tenants.add(item.get('tenant_id', {}).get('S', ''))
                else:
                    user_count += 1
                    role = item.get('role', {}).get('S', '')
                    if role == 'admin':
                        admin_count += 1
            
            return {
                'total_tenants': tenant_count,
                'total_users': user_count,
                'admin_users': admin_count,
                'regular_users': user_count - admin_count,
                'active_tenants': list(tenants)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_storage_usage(self) -> Dict:
        """Get S3 storage usage statistics."""
        try:
            # Get bucket size (this is a simplified version - in production you'd use CloudWatch metrics)
            paginator = self.s3.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket_name)
            
            total_size = 0
            total_objects = 0
            tenant_usage = {}
            
            for page in pages:
                for obj in page.get('Contents', []):
                    total_size += obj['Size']
                    total_objects += 1
                    
                    # Extract tenant ID from key
                    key_parts = obj['Key'].split('/')
                    if len(key_parts) > 0:
                        tenant_id = key_parts[0]
                        if tenant_id not in tenant_usage:
                            tenant_usage[tenant_id] = {'size': 0, 'objects': 0}
                        tenant_usage[tenant_id]['size'] += obj['Size']
                        tenant_usage[tenant_id]['objects'] += 1
            
            return {
                'total_size_bytes': total_size,
                'total_size_gb': round(total_size / (1024**3), 2),
                'total_objects': total_objects,
                'tenant_usage': tenant_usage
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_recent_activity(self, hours: int = 24) -> Dict:
        """Get recent activity from CloudWatch logs (simplified version)."""
        try:
            # This would typically query CloudWatch Insights for Transfer Family logs
            # For now, returning a placeholder structure
            return {
                'period_hours': hours,
                'note': 'Full log analysis requires CloudWatch Insights queries',
                'placeholder_data': {
                    'total_connections': 'N/A',
                    'successful_transfers': 'N/A',
                    'failed_connections': 'N/A'
                }
            }
        except Exception as e:
            return {'error': str(e)}
    
    def generate_report(self) -> Dict:
        """Generate a comprehensive platform report."""
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'platform': 'FTPme Centralized File Exchange',
            'infrastructure_health': self.check_infrastructure_health(),
            'tenant_statistics': self.get_tenant_statistics(),
            'storage_usage': self.get_storage_usage(),
            'recent_activity': self.get_recent_activity()
        }
        
        return report
    
    def print_report(self, report: Dict = None):
        """Print a formatted report to console."""
        if not report:
            report = self.generate_report()
        
        print("=" * 60)
        print("🚀 FTPme Platform Status Report")
        print("=" * 60)
        print(f"Generated: {report['report_timestamp']}")
        print()
        
        # Infrastructure Health
        health = report['infrastructure_health']
        print("🏗️  Infrastructure Health:")
        print(f"   Overall Status: {'✅' if health['overall_status'] == 'healthy' else '❌'} {health['overall_status'].upper()}")
        
        for component, status in health['components'].items():
            emoji = '✅' if status['status'] == 'healthy' else '❌'
            print(f"   {component}: {emoji} {status['status']}")
        print()
        
        # Tenant Statistics
        stats = report['tenant_statistics']
        if 'error' not in stats:
            print("👥 Tenant Statistics:")
            print(f"   Total Tenants: {stats['total_tenants']}")
            print(f"   Total Users: {stats['total_users']}")
            print(f"   Admin Users: {stats['admin_users']}")
            print(f"   Regular Users: {stats['regular_users']}")
            print()
        
        # Storage Usage
        storage = report['storage_usage']
        if 'error' not in storage:
            print("💾 Storage Usage:")
            print(f"   Total Size: {storage['total_size_gb']} GB")
            print(f"   Total Objects: {storage['total_objects']}")
            print(f"   Active Tenants: {len(storage['tenant_usage'])}")
            print()
        
        print("=" * 60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='FTPme Platform Monitor')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--save', type=str, help='Save report to file')
    
    args = parser.parse_args()
    
    # Check environment variables
    required_vars = ['TRANSFER_SERVER_ID', 'TENANT_TABLE_NAME']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {missing_vars}")
        print("Please run: source setup_env.sh")
        return
    
    monitor = FTPmeMonitor()
    report = monitor.generate_report()
    
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        monitor.print_report(report)
    
    if args.save:
        with open(args.save, 'w') as f:
            json.dumps(report, f, indent=2)
        print(f"\n📁 Report saved to: {args.save}")

if __name__ == "__main__":
    main() 