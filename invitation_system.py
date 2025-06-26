#!/usr/bin/env python3
import boto3
import json
import uuid
import smtplib
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class InvitationSystem:
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.ses = boto3.client('ses')
        self.invitations_table = self.dynamodb.Table('FileExchangeInvitations')
        self.users_table = self.dynamodb.Table('FileExchangeUsers')
        
        # Email configuration based on environment
        self.is_development = os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEBUG', 'False').lower() == 'true'
        
        if self.is_development:
            # For development: use verified email or mock
            self.sender_email = os.environ.get('SES_VERIFIED_EMAIL', 'test@example.com')
            self.mock_email = os.environ.get('MOCK_EMAIL', 'False').lower() == 'true'
        else:
            # For production: use custom domain
            self.sender_email = 'noreply@ftpme.com'
            self.mock_email = False
        
    def invite_internal_user(self, tenant_id, drop_id, inviter_email, invitee_email, role='member'):
        """Invite an internal company user to a drop"""
        
        invitation_id = str(uuid.uuid4())
        expires_at = (datetime.utcnow() + timedelta(days=7)).isoformat()
        
        invitation = {
            'invitation_id': invitation_id,
            'tenant_id': tenant_id,
            'drop_id': drop_id,
            'inviter_email': inviter_email,
            'invitee_email': invitee_email,
            'user_type': 'internal',
            'role': role,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at
        }
        
        # Store invitation
        self.invitations_table.put_item(Item=invitation)
        
        # Send email
        self._send_internal_invitation_email(invitation)
        
        return invitation_id
    
    def invite_external_user(self, tenant_id, drop_id, inviter_email, invitee_email, 
                           company_name, permissions=['read']):
        """Invite an external user from another company to a drop"""
        
        invitation_id = str(uuid.uuid4())
        expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
        
        invitation = {
            'invitation_id': invitation_id,
            'tenant_id': tenant_id,
            'drop_id': drop_id,
            'inviter_email': inviter_email,
            'invitee_email': invitee_email,
            'user_type': 'external',
            'company_name': company_name,
            'permissions': permissions,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at
        }
        
        # Store invitation
        self.invitations_table.put_item(Item=invitation)
        
        # Send email
        self._send_external_invitation_email(invitation)
        
        return invitation_id
    
    def accept_invitation(self, invitation_id, user_info):
        """Accept an invitation and create user access"""
        
        # Get invitation
        response = self.invitations_table.get_item(
            Key={'invitation_id': invitation_id}
        )
        
        if 'Item' not in response:
            raise ValueError("Invitation not found")
        
        invitation = response['Item']
        
        if invitation['status'] != 'pending':
            raise ValueError("Invitation already processed")
        
        if datetime.fromisoformat(invitation['expires_at']) < datetime.utcnow():
            raise ValueError("Invitation expired")
        
        # Create user access
        if invitation['user_type'] == 'internal':
            self._create_internal_user_access(invitation, user_info)
        else:
            self._create_external_user_access(invitation, user_info)
        
        # Mark invitation as accepted
        self.invitations_table.update_item(
            Key={'invitation_id': invitation_id},
            UpdateExpression='SET #status = :status, accepted_at = :accepted_at',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'accepted',
                ':accepted_at': datetime.utcnow().isoformat()
            }
        )
        
        return True
    
    def _create_internal_user_access(self, invitation, user_info):
        """Create internal user access to the drop"""
        
        user_id = f"{invitation['tenant_id']}-{user_info['username']}"
        
        user_record = {
            'tenant_id': invitation['tenant_id'],
            'user_id': user_id,
            'email': invitation['invitee_email'],
            'username': user_info['username'],
            'role': invitation['role'],
            'user_type': 'internal',
            'drops_access': [invitation['drop_id']],
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }
        
        self.users_table.put_item(Item=user_record)
    
    def _create_external_user_access(self, invitation, user_info):
        """Create external user access to the drop"""
        
        user_id = f"external-{str(uuid.uuid4())}"
        
        user_record = {
            'tenant_id': f"external-{invitation['tenant_id']}",
            'user_id': user_id,
            'email': invitation['invitee_email'],
            'username': user_info['username'],
            'company_name': invitation['company_name'],
            'user_type': 'external',
            'host_tenant_id': invitation['tenant_id'],
            'drops_access': [invitation['drop_id']],
            'permissions': invitation['permissions'],
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }
        
        self.users_table.put_item(Item=user_record)
    
    def _send_internal_invitation_email(self, invitation):
        """Send invitation email to internal user"""
        
        subject = f"You've been invited to collaborate on FTPme"
        
        body = f"""
        Hi there,
        
        You've been invited to join a secure collaboration space on FTPme.
        
        Drop: {invitation.get('drop_name', 'Collaboration Space')}
        Invited by: {invitation['inviter_email']}
        Role: {invitation['role'].title()}
        
        Click here to accept: https://ftpme.com/accept-invitation/{invitation['invitation_id']}
        
        This invitation expires in 7 days.
        
        Best regards,
        The FTPme Team
        """
        
        self._send_email(invitation['invitee_email'], subject, body)
    
    def _send_external_invitation_email(self, invitation):
        """Send invitation email to external user"""
        
        subject = f"Secure file sharing invitation from {invitation['inviter_email']}"
        
        body = f"""
        Hi there,
        
        {invitation['inviter_email']} has invited you to securely share files on FTPme.
        
        Drop: {invitation.get('drop_name', 'Collaboration Space')}
        Your company: {invitation['company_name']}
        Access level: {', '.join(invitation['permissions'])}
        
        Click here to get started: https://ftpme.com/accept-invitation/{invitation['invitation_id']}
        
        FTPme is a secure business file sharing platform. No software to install - just click the link above.
        
        This invitation expires in 30 days.
        
        Best regards,
        The FTPme Team
        """
        
        self._send_email(invitation['invitee_email'], subject, body)
    
    def _send_email(self, to_email, subject, body):
        """Send email via SES or mock for development"""
        
        if self.mock_email:
            # Mock email for development
            print("🔥 MOCK EMAIL SENT 🔥")
            print(f"TO: {to_email}")
            print(f"FROM: {self.sender_email}")
            print(f"SUBJECT: {subject}")
            print(f"BODY:\n{body}")
            print("="*60)
            return
        
        try:
            response = self.ses.send_email(
                Source=self.sender_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Text': {'Data': body}}
                }
            )
            print(f"✅ Email sent to {to_email}: {response['MessageId']}")
        except Exception as e:
            print(f"❌ Failed to send email to {to_email}: {e}")
            if self.is_development:
                # For development, also print the email content
                print(f"📧 EMAIL CONTENT (would have been sent):")
                print(f"TO: {to_email}")
                print(f"FROM: {self.sender_email}")
                print(f"SUBJECT: {subject}")
                print(f"BODY:\n{body}")
                print("="*60)

# Example usage
if __name__ == "__main__":
    invitation_system = InvitationSystem()
    
    # Invite internal user
    invitation_id = invitation_system.invite_internal_user(
        tenant_id='a02678d0-8ad8-4510-b1a4-92b2701a19f5',
        drop_id='investors',
        inviter_email='admin@testcompany.com',
        invitee_email='cfo@testcompany.com',
        role='admin'
    )
    print(f"Internal invitation sent: {invitation_id}")
    
    # Invite external user
    external_invitation_id = invitation_system.invite_external_user(
        tenant_id='a02678d0-8ad8-4510-b1a4-92b2701a19f5',
        drop_id='investors',
        inviter_email='admin@testcompany.com',
        invitee_email='analyst@vc-firm.com',
        company_name='VC Partners LLC',
        permissions=['read', 'download']
    )
    print(f"External invitation sent: {external_invitation_id}") 