from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import boto3
import os
import json
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from create_tenant import TenantManager
from manage_users import UserManager
from invitation_system import InvitationSystem
from botocore.exceptions import ClientError
import tempfile
from datetime import datetime
import mimetypes

app = Flask(__name__)
# Use a fixed secret key for development (change for production)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-for-production')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set environment variables for the new architecture
# These should be set from CDK outputs or deployment configuration
if not os.environ.get('S3_BUCKET_NAME'):
    os.environ['S3_BUCKET_NAME'] = ''  # Will be set by deployment script
if not os.environ.get('TRANSFER_SERVER_ID'):
    # This should be set from CDK output - using placeholder for now
    os.environ['TRANSFER_SERVER_ID'] = 'TRANSFER_SERVER_ID_FROM_CDK'
if not os.environ.get('TENANT_TABLE_NAME'):
    # This should be set from CDK output - using placeholder for now  
    os.environ['TENANT_TABLE_NAME'] = 'TENANT_TABLE_FROM_CDK'

# Initialize AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.client('dynamodb')

def get_user_from_session():
    """Get user information from session"""
    if 'user_tenant_id' in session and 'user_username' in session:
        return {
            'tenant_id': session['user_tenant_id'],
            'username': session['user_username'],
            'email': session.get('user_email', ''),
            'role': session.get('user_role', 'user'),
            'sftp_username': session.get('user_sftp_username', '')
        }
    return None

def get_s3_path(tenant_id, path=''):
    """Get the full S3 path for a tenant"""
    if path.startswith('/'):
        path = path[1:]
    return f"{tenant_id}/{path}" if path else f"{tenant_id}/"

def list_s3_files(tenant_id, prefix=''):
    """List files in S3 for a tenant"""
    try:
        bucket_name = os.environ['S3_BUCKET_NAME']
        s3_prefix = get_s3_path(tenant_id, prefix)
        
        # Ensure prefix ends with slash for proper directory listing
        if not s3_prefix.endswith('/'):
            s3_prefix += '/'
        
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=s3_prefix,
            Delimiter='/'
        )
        
        files = []
        folders = []
        
        # Process folders (common prefixes)
        for prefix_info in response.get('CommonPrefixes', []):
            folder_name = prefix_info['Prefix'].replace(s3_prefix, '').rstrip('/')
            if folder_name:
                folders.append({
                    'name': folder_name,
                    'type': 'folder',
                    'path': prefix_info['Prefix'].replace(f"{tenant_id}/", '').rstrip('/')
                })
        
        # Process files
        for obj in response.get('Contents', []):
            # Skip the folder itself and empty objects
            if obj['Key'] == s3_prefix or obj['Key'].endswith('/'):
                continue
                
            file_name = obj['Key'].replace(s3_prefix, '')
            if '/' not in file_name:  # Only files in current directory
                files.append({
                    'name': file_name,
                    'type': 'file',
                    'size': obj['Size'],
                    'modified': obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S'),
                    'path': obj['Key'].replace(f"{tenant_id}/", '')
                })
        
        return sorted(folders, key=lambda x: x['name']) + sorted(files, key=lambda x: x['name'])
    
    except Exception as e:
        print(f"Error listing S3 files: {e}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        tenant_id = request.form['tenant_id'].strip()
        username = request.form['username'].strip()
        
        if not tenant_id or not username:
            flash('Both Tenant ID and Username are required')
            return redirect(request.url)
        
        try:
            # Look up user in DynamoDB
            response = dynamodb.get_item(
                TableName=os.environ['TENANT_TABLE_NAME'],
                Key={
                    'tenant_id': {'S': tenant_id},
                    'user_id': {'S': username}
                }
            )
            
            if 'Item' not in response:
                flash('Invalid tenant ID or username')
                return redirect(request.url)
            
            user_data = response['Item']
            
            # Store user info in session
            session['user_tenant_id'] = tenant_id
            session['user_username'] = username
            session['user_email'] = user_data.get('email', {}).get('S', '')
            session['user_role'] = user_data.get('role', {}).get('S', 'user')
            session['user_sftp_username'] = user_data.get('sftp_username', {}).get('S', '')
            
            flash(f'Welcome back, {username}!')
            return redirect(url_for('drops_dashboard'))
            
        except Exception as e:
            flash(f'Error during login: {str(e)}')
            return redirect(request.url)
    
    return render_template('login.html')











@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        company_name = request.form['company_name'].strip()
        admin_name = request.form['admin_name'].strip()
        admin_email = request.form['admin_email'].strip()
        
        if not all([company_name, admin_name, admin_email]):
            flash('All fields are required')
            return redirect(request.url)
        
        try:
            # Create tenant using new centralized architecture
            manager = TenantManager()
            result = manager.create_tenant(
                company_name=company_name,
                admin_email=admin_email,
                admin_username=admin_name,
                admin_ssh_key=""  # Generate a default SSH key or handle later
            )
            
            # Store tenant info in session
            session['tenant_id'] = result['tenant_id']
            session['admin_username'] = result['admin_username']
            session['sftp_username'] = result['sftp_username']
            session['server_endpoint'] = f"{result['server_id']}.server.transfer.{boto3.Session().region_name}.amazonaws.com"
            
            flash(f'Company workspace created successfully!')
            return redirect(url_for('workspace_created', workspace_id=result['tenant_id']))
            
        except Exception as e:
            flash(f'Error creating workspace: {str(e)}')
            return redirect(request.url)
    
    return render_template('create_user.html')

@app.route('/workspace-created/<workspace_id>')
def workspace_created(workspace_id):
    # Verify the workspace ID exists in session (security check)
    if session.get('tenant_id') != workspace_id:
        flash('Invalid workspace access')
        return redirect(url_for('index'))
    
    return render_template('workspace_created.html', workspace_id=workspace_id)

def get_tenant_drops(tenant_id):
    """Get all drops for a tenant from DynamoDB and S3"""
    drops = []
    
    try:
        # First, get drops from DynamoDB
        response = dynamodb.scan(
            TableName=os.environ['TENANT_TABLE_NAME'],
            FilterExpression='tenant_id = :tid AND begins_with(user_id, :drop_prefix)',
            ExpressionAttributeValues={
                ':tid': {'S': tenant_id},
                ':drop_prefix': {'S': 'DROP#'}
            }
        )
        
        db_drops = {}
        for item in response.get('Items', []):
            drop_id = item['user_id']['S'].replace('DROP#', '')
            drop_data = {
                'id': drop_id,
                'name': item.get('drop_name', {}).get('S', ''),
                'purpose': item.get('drop_purpose', {}).get('S', ''),
                'color': item.get('drop_color', {}).get('S', 'blue'),
                'created_at': item.get('created_at', {}).get('S', ''),
                'internal_users': item.get('internal_users', {}).get('L', []),
                'external_users': item.get('external_users', {}).get('L', []),
                'source': 'database'
            }
            db_drops[drop_id] = drop_data
            drops.append(drop_data)
        
        # Also check S3 for drop folders that might not be in DynamoDB
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        if bucket_name:
            try:
                response = s3_client.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=f"{tenant_id}/drops/",
                    Delimiter='/'
                )
                
                for prefix_info in response.get('CommonPrefixes', []):
                    # Extract drop ID from S3 prefix like "tenant/drops/drop-id/"
                    drop_path = prefix_info['Prefix']
                    drop_id = drop_path.replace(f"{tenant_id}/drops/", "").rstrip('/')
                    
                    if drop_id and drop_id not in db_drops:
                        # This drop exists in S3 but not in database
                        drop_data = {
                            'id': drop_id,
                            'name': drop_id.replace('-', ' ').title(),
                            'purpose': 'Legacy drop (detected from files)',
                            'color': 'gray',
                            'created_at': '',
                            'internal_users': [],
                            'external_users': [],
                            'source': 's3_detected'
                        }
                        drops.append(drop_data)
                        print(f"Detected legacy drop from S3: {drop_id}")
                        
            except Exception as s3_e:
                print(f"Error checking S3 for drops: {s3_e}")
        
        return drops
        
    except Exception as e:
        print(f"Error getting tenant drops: {e}")
        return []

def get_tenant_users_count(tenant_id):
    """Get count of users for a tenant"""
    try:
        response = dynamodb.scan(
            TableName=os.environ['TENANT_TABLE_NAME'],
            FilterExpression='tenant_id = :tid AND NOT begins_with(user_id, :drop_prefix) AND user_id <> :metadata',
            ExpressionAttributeValues={
                ':tid': {'S': tenant_id},
                ':drop_prefix': {'S': 'DROP#'},
                ':metadata': {'S': 'TENANT_METADATA'}
            }
        )
        return len(response.get('Items', []))
    except Exception as e:
        print(f"Error getting user count: {e}")
        return 0

def get_tenant_files_count(tenant_id):
    """Get total file count for a tenant from S3 - only files within drops"""
    try:
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        if not bucket_name:
            print("S3_BUCKET_NAME not configured, returning 0 file count")
            return 0
            
        # Only count files within drops
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f"{tenant_id}/drops/",
            MaxKeys=1000  # Limit for performance
        )
        
        # Count actual files (not directories)
        file_count = 0
        for obj in response.get('Contents', []):
            if not obj['Key'].endswith('/'):  # Skip directory markers
                file_count += 1
        
        return file_count
    except Exception as e:
        print(f"Error getting file count (S3 may not be configured): {e}")
        return 0

def get_drop_files_count(tenant_id, drop_id):
    """Get file count for a specific drop"""
    try:
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        if not bucket_name:
            return 0
            
        drop_prefix = f"{tenant_id}/drops/{drop_id}/"
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=drop_prefix
        )
        
        file_count = 0
        for obj in response.get('Contents', []):
            if not obj['Key'].endswith('/'):  # Skip directory markers
                file_count += 1
        
        return file_count
    except Exception as e:
        print(f"Error getting drop file count (S3 may not be configured): {e}")
        return 0

def get_recent_activity_count(tenant_id, days=7):
    """Get count of recent file activities"""
    try:
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        if not bucket_name:
            return 0
            
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f"{tenant_id}/"
        )
        
        recent_count = 0
        for obj in response.get('Contents', []):
            if obj['LastModified'].replace(tzinfo=None) > cutoff_date:
                recent_count += 1
        
        return recent_count
    except Exception as e:
        print(f"Error getting recent activity (S3 may not be configured): {e}")
        return 0

@app.route('/drops')
def drops_dashboard():
    user = get_user_from_session()
    if not user:
        return redirect(url_for('login'))
    
    # Get real data from database and S3
    drops = get_tenant_drops(user['tenant_id'])
    
    # Calculate file counts for each drop
    for drop in drops:
        drop['files_count'] = get_drop_files_count(user['tenant_id'], drop['id'])
        # Convert DynamoDB lists to Python lists for counting
        if isinstance(drop['internal_users'], list) and drop['internal_users'] and isinstance(drop['internal_users'][0], dict):
            drop['internal_users'] = [item.get('S', '') for item in drop['internal_users']]
        elif not isinstance(drop['internal_users'], list):
            drop['internal_users'] = []
            
        if isinstance(drop['external_users'], list) and drop['external_users'] and isinstance(drop['external_users'][0], dict):
            drop['external_users'] = [item.get('S', '') for item in drop['external_users']]
        elif not isinstance(drop['external_users'], list):
            drop['external_users'] = []
    
    # Calculate dashboard statistics
    total_drops = len(drops)
    total_collaborators = get_tenant_users_count(user['tenant_id'])
    total_files = get_tenant_files_count(user['tenant_id'])
    recent_activity = get_recent_activity_count(user['tenant_id'])
    
    # Add unique collaborator count from all drops
    all_collaborators = set()
    for drop in drops:
        all_collaborators.update(drop['internal_users'])
        all_collaborators.update(drop['external_users'])
    total_collaborators = max(total_collaborators, len(all_collaborators))
    
    # Additional activity data for the modal
    recent_uploads = 1  # Files uploaded in last 7 days
    new_collaborators = 0  # New collaborators added in last 7 days
    new_drops = len([d for d in drops if d.get('created_at')])  # Drops created (all are recent in this demo)
    
    # Get actual user list for the collaborators modal
    try:
        response = dynamodb.scan(
            TableName=os.environ['TENANT_TABLE_NAME'],
            FilterExpression='tenant_id = :tid AND NOT begins_with(user_id, :drop_prefix) AND user_id <> :metadata',
            ExpressionAttributeValues={
                ':tid': {'S': user['tenant_id']},
                ':drop_prefix': {'S': 'DROP#'},
                ':metadata': {'S': 'TENANT_METADATA'}
            }
        )
        
        tenant_users = []
        for item in response.get('Items', []):
            tenant_users.append({
                'user_id': item.get('user_id', {}).get('S', ''),
                'username': item.get('username', {}).get('S', ''),
                'email': item.get('email', {}).get('S', ''),
                'role': item.get('role', {}).get('S', ''),
                'sftp_username': item.get('sftp_username', {}).get('S', '')
            })
    except Exception as e:
        print(f"Error getting tenant users: {e}")
        tenant_users = []
    
    return render_template('drops_dashboard.html', 
                         user=user, 
                         drops=drops,
                         total_drops=total_drops,
                         total_collaborators=total_collaborators,
                         total_files=total_files,
                         recent_activity=recent_activity,
                         recent_uploads=recent_uploads,
                         new_collaborators=new_collaborators,
                         new_drops=new_drops,
                         tenant_users=tenant_users)

@app.route('/drops/create', methods=['POST'])
def create_drop():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    drop_name = data.get('name', '').strip()
    drop_purpose = data.get('purpose', '').strip()
    drop_color = data.get('color', 'blue')
    
    if not drop_name:
        return jsonify({'error': 'Drop name is required'}), 400
    
    try:
        # Generate drop ID from name
        import uuid
        from datetime import datetime
        
        drop_id = drop_name.lower().replace(' ', '-').replace('_', '-')
        # Ensure uniqueness by adding timestamp if needed
        drop_id = f"{drop_id}-{int(datetime.now().timestamp())}"
        
        # Save drop to DynamoDB
        dynamodb.put_item(
            TableName=os.environ['TENANT_TABLE_NAME'],
            Item={
                'tenant_id': {'S': user['tenant_id']},
                'user_id': {'S': f'DROP#{drop_id}'},
                'drop_name': {'S': drop_name},
                'drop_purpose': {'S': drop_purpose},
                'drop_color': {'S': drop_color},
                'created_at': {'S': datetime.now().isoformat()},
                'created_by': {'S': user['username']},
                'internal_users': {'L': [{'S': user['username']}]},  # Creator is always internal
                'external_users': {'L': []}
            }
        )
        
        # Create drop folder in S3
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        if bucket_name:
            s3_client.put_object(
                Bucket=bucket_name,
                Key=f"{user['tenant_id']}/drops/{drop_id}/.keep",
                Body=b''
            )
        
        return jsonify({'success': True, 'message': f'Drop "{drop_name}" created successfully'})
        
    except Exception as e:
        print(f"Error creating drop: {e}")
        return jsonify({'error': f'Failed to create drop: {str(e)}'}), 500

def get_drop_by_id(tenant_id, drop_id):
    """Get a specific drop from DynamoDB"""
    try:
        response = dynamodb.get_item(
            TableName=os.environ['TENANT_TABLE_NAME'],
            Key={
                'tenant_id': {'S': tenant_id},
                'user_id': {'S': f'DROP#{drop_id}'}
            }
        )
        
        if 'Item' not in response:
            return None
            
        item = response['Item']
        return {
            'id': drop_id,
            'name': item.get('drop_name', {}).get('S', drop_id.replace('-', ' ').title()),
            'purpose': item.get('drop_purpose', {}).get('S', ''),
            'color': item.get('drop_color', {}).get('S', 'blue'),
            'created_at': item.get('created_at', {}).get('S', ''),
            'created_by': item.get('created_by', {}).get('S', ''),
            'internal_users': [item.get('S', '') for item in item.get('internal_users', {}).get('L', [])],
            'external_users': [item.get('S', '') for item in item.get('external_users', {}).get('L', [])]
        }
    except Exception as e:
        print(f"Error getting drop: {e}")
        return None

@app.route('/drops/<drop_id>/files')
def drop_files(drop_id):
    user = get_user_from_session()
    if not user:
        return redirect(url_for('login'))
    
    # Get real drop data from database
    drop = get_drop_by_id(user['tenant_id'], drop_id)
    if not drop:
        # Fallback for backwards compatibility
        drop = {
            'id': drop_id,
            'name': drop_id.replace('-', ' ').title()
        }
    
    # This would load the specific drop and its files
    # For now, redirect to the existing file manager with a drop context
    current_path = request.args.get('path', f'drops/{drop_id}')
    files = list_s3_files(user['tenant_id'], current_path)
    
    # Build breadcrumb navigation
    breadcrumbs = [
        {'name': 'Drops', 'path': '/drops'},
        {'name': drop['name'], 'path': f'drops/{drop_id}'}
    ]
    if current_path != f'drops/{drop_id}':
        parts = current_path.replace(f'drops/{drop_id}/', '').split('/')
        path_so_far = f'drops/{drop_id}'
        for part in parts:
            if part:
                path_so_far += f"/{part}"
                breadcrumbs.append({'name': part, 'path': path_so_far})
    
    return render_template('drop_files.html', 
                         user=user, 
                         drop=drop,
                         files=files, 
                         current_path=current_path,
                         breadcrumbs=breadcrumbs)

@app.route('/drops/<drop_id>/settings')
def drop_settings(drop_id):
    user = get_user_from_session()
    if not user:
        return redirect(url_for('login'))
    
    # Get real drop data from database
    drop = get_drop_by_id(user['tenant_id'], drop_id)
    if not drop:
        # Fallback for backwards compatibility
        drop = {
            'id': drop_id,
            'name': drop_id.replace('-', ' ').title()
        }
    
    # This would load the drop settings page
    return render_template('drop_settings.html', 
                         user=user, 
                         drop=drop)

@app.route('/dashboard')
def dashboard():
    if 'tenant_id' not in session:
        return redirect(url_for('index'))
    
    try:
        user_manager = UserManager(session['tenant_id'])
        users = user_manager.list_users()
        
        # Add connection info to context
        server_endpoint = session.get('server_endpoint', 'SFTP_SERVER_ENDPOINT')
        
        return render_template('dashboard.html', 
                             users=users, 
                             server_endpoint=server_endpoint,
                             tenant_id=session['tenant_id'])
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return redirect(url_for('index'))

@app.route('/users/create', methods=['GET', 'POST'])
def create_user():
    if 'tenant_id' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        user_role = request.form.get('role', 'user')  # Default to 'user' role
        
        # Handle SSH key from textarea (not file upload)
        ssh_key = request.form.get('ssh_key', '').strip()
        if not ssh_key:
            flash('SSH key is required')
            return redirect(request.url)
        
        try:
            user_manager = UserManager(session['tenant_id'])
            result = user_manager.create_user(
                username=username,
                email=email,
                ssh_key=ssh_key,
                role=user_role
            )
            
            flash(f'User created successfully! SFTP username: {result["sftp_username"]}')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error creating user: {str(e)}')
            return redirect(request.url)
    
    return render_template('create_user.html')

@app.route('/users/delete/<username>')
def delete_user(username):
    if 'tenant_id' not in session:
        return redirect(url_for('index'))
    
    try:
        user_manager = UserManager(session['tenant_id'])
        user_manager.delete_user(username)
        flash(f'User {username} deleted successfully!')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}')
    
    return redirect(url_for('dashboard'))

@app.route('/user-logout')
def user_logout():
    # Clear only user session data, keep tenant admin session if exists
    user_keys = ['user_tenant_id', 'user_username', 'user_email', 'user_role', 'user_sftp_username']
    for key in user_keys:
        session.pop(key, None)
    flash('You have been logged out successfully.')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('index'))

# External User Invitation Routes
@app.route('/api/invite-external-user', methods=['POST'])
def invite_external_user():
    """Send invitation to external user"""
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        company_name = data.get('company_name', '').strip()
        drop_ids = data.get('drop_ids', [])  # List of drop IDs to invite to
        permissions = data.get('permissions', ['read'])
        message = data.get('message', '').strip()
        
        if not email or not company_name:
            return jsonify({'error': 'Email and company name are required'}), 400
        
        if not drop_ids:
            return jsonify({'error': 'At least one drop must be selected'}), 400
        
        # Initialize invitation system
        invitation_system = InvitationSystem()
        
        # Send invitations for each selected drop
        invitation_ids = []
        for drop_id in drop_ids:
            invitation_id = invitation_system.invite_external_user(
                tenant_id=user['tenant_id'],
                drop_id=drop_id,
                inviter_email=user['email'],
                invitee_email=email,
                company_name=company_name,
                permissions=permissions
            )
            invitation_ids.append(invitation_id)
        
        return jsonify({
            'success': True, 
            'message': f'Invitation sent to {email}',
            'invitation_ids': invitation_ids
        })
        
    except Exception as e:
        print(f"Error sending invitation: {e}")
        return jsonify({'error': f'Failed to send invitation: {str(e)}'}), 500

@app.route('/accept-invitation/<invitation_id>')
def accept_invitation_page(invitation_id):
    """Landing page for external users to accept invitations"""
    try:
        # Get invitation details
        invitation_system = InvitationSystem()
        dynamodb_resource = boto3.resource('dynamodb')
        invitations_table = dynamodb_resource.Table('FileExchangeInvitations')
        
        response = invitations_table.get_item(Key={'invitation_id': invitation_id})
        
        if 'Item' not in response:
            flash('Invitation not found or expired')
            return render_template('invitation_error.html', error='Invitation not found')
        
        invitation = response['Item']
        
        # Check if invitation is still valid
        if invitation['status'] != 'pending':
            flash('This invitation has already been processed')
            return render_template('invitation_error.html', error='Invitation already processed')
        
        from datetime import datetime
        if datetime.fromisoformat(invitation['expires_at']) < datetime.utcnow():
            flash('This invitation has expired')
            return render_template('invitation_error.html', error='Invitation expired')
        
        return render_template('accept_invitation.html', invitation=invitation)
        
    except Exception as e:
        print(f"Error loading invitation: {e}")
        flash('Error loading invitation')
        return render_template('invitation_error.html', error='Error loading invitation')

@app.route('/accept-invitation/<invitation_id>', methods=['POST'])
def accept_invitation(invitation_id):
    """Process invitation acceptance"""
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()  # For external user account
        
        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('accept_invitation_page', invitation_id=invitation_id))
        
        # Accept the invitation
        invitation_system = InvitationSystem()
        user_info = {
            'username': username,
            'password': password
        }
        
        invitation_system.accept_invitation(invitation_id, user_info)
        
        flash('Invitation accepted successfully! You can now access the shared files.')
        return render_template('invitation_accepted.html', username=username)
        
    except Exception as e:
        print(f"Error accepting invitation: {e}")
        flash(f'Error accepting invitation: {str(e)}')
        return redirect(url_for('accept_invitation_page', invitation_id=invitation_id))

@app.route('/api/list-invitations')
def list_invitations():
    """List invitations for current tenant"""
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        dynamodb_resource = boto3.resource('dynamodb')
        invitations_table = dynamodb_resource.Table('FileExchangeInvitations')
        
        # Query invitations for this tenant
        response = invitations_table.scan(
            FilterExpression='tenant_id = :tenant_id',
            ExpressionAttributeValues={':tenant_id': user['tenant_id']}
        )
        
        invitations = response.get('Items', [])
        
        return jsonify({'invitations': invitations})
        
    except Exception as e:
        print(f"Error listing invitations: {e}")
        return jsonify({'error': f'Failed to list invitations: {str(e)}'}), 500

if __name__ == '__main__':
    # Check required environment variables
    required_vars = ['TRANSFER_SERVER_ID', 'TENANT_TABLE_NAME']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Warning: Missing required environment variables: {missing_vars}")
        print("Please set these from your CDK deployment outputs.")
    
    app.run(debug=True, port=5001)