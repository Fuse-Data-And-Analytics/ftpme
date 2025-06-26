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
        
        # Send welcome email with login credentials
        self._send_welcome_email(invitation, user_info)
        
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
        
        # Hash password for security
        import hashlib
        password_hash = hashlib.sha256(user_info['password'].encode()).hexdigest()
        
        user_record = {
            'tenant_id': f"external-{invitation['tenant_id']}",
            'user_id': user_id,
            'email': invitation['invitee_email'],
            'username': user_info['username'],
            'password_hash': password_hash,
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
        
        subject = f"File Sharing Invitation from {invitation['inviter_email'].split('@')[0]}"
        
        body = f"""Hello,

You've been invited to securely collaborate on a file sharing workspace.

INVITATION DETAILS:
• Invited by: {invitation['inviter_email']}
• Your company: {invitation['company_name']}
• Workspace: {invitation.get('drop_name', 'Collaboration Space')}
• Access permissions: {', '.join(invitation['permissions'])}

NEXT STEPS:
1. Click this secure link: https://ftpme.com/accept-invitation/{invitation['invitation_id']}
2. Create your account (takes 2 minutes)
3. Start collaborating securely

ABOUT FTPME:
FTPme is a professional file exchange platform trusted by businesses for secure document sharing. No software installation required - everything works in your web browser.

This invitation expires in 30 days for security purposes.

If you have questions, please contact {invitation['inviter_email']} directly.

Best regards,
Dave Findlay
Fuse Data & Analytics
dave@fusedata.co

---
This email was sent because {invitation['inviter_email']} invited you to collaborate via FTPme.
If you believe this was sent in error, please contact dave@fusedata.co."""
        
        self._send_email(invitation['invitee_email'], subject, body)
    
    def _send_welcome_email(self, invitation, user_info):
        """Send welcome email with login credentials after account creation"""
        
        subject = f"Welcome to FTPme - Your Account is Ready!"
        
        if invitation['user_type'] == 'external':
            body = f"""Welcome to FTPme, {user_info['username']}!

Your account has been successfully created and you now have secure access to the shared files.

LOGIN CREDENTIALS:
• Website: https://ftpme.com/login
• Username: {user_info['username']}
• Password: {user_info['password']}

WHAT YOU CAN ACCESS:
• Workspace: {invitation.get('drop_name', 'Collaboration Space')}
• Permissions: {', '.join(invitation['permissions'])}
• Invited by: {invitation['inviter_email']}
• Your company: {invitation['company_name']}

GETTING STARTED:
1. Visit https://ftpme.com/login
2. Enter your username and password above
3. You'll see the shared files in your dashboard
4. Use the file browser to view, download, or upload files (based on your permissions)

SECURITY NOTICE:
• Please keep your login credentials secure
• Your access is limited to the specific files you've been invited to
• FTPme uses enterprise-grade security to protect all shared data

If you need help or have questions about the shared files, please contact {invitation['inviter_email']} directly.

Welcome to secure file collaboration!

Best regards,
Dave Findlay
Fuse Data & Analytics
dave@fusedata.co

---
This email contains your login credentials. Please store them securely and delete this email after logging in."""
        else:
            # Internal user welcome
            body = f"""Welcome to FTPme, {user_info['username']}!

Your internal account has been successfully created.

LOGIN CREDENTIALS:
• Website: https://ftpme.com/login
• Username: {user_info['username']}
• Role: {invitation['role'].title()}

You now have access to the {invitation.get('drop_name', 'collaboration space')} and can start collaborating with your team.

Best regards,
The FTPme Team"""
        
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