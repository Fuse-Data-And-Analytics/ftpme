# FTPme - Secure File Exchange Platform

A modern, secure file exchange platform built with Flask and AWS services. FTPme provides organizations with a secure way to share files internally and with external collaborators through "drops" - organized file sharing spaces.

## 🚀 Features

### Core Functionality
- **Secure File Drops**: Create organized spaces for file sharing
- **Multi-tenant Architecture**: Support for multiple organizations
- **User Management**: Internal users and external guest access
- **External User Invitations**: Invite partners, clients, and vendors from other companies
- **Interactive Dashboard**: Real-time metrics and management interface
- **File Browser**: Navigate and manage files within drops
- **SFTP Integration**: Secure file transfer protocol support

### User Management & Authentication
- **Dual User Types**: Internal company users and external collaborators
- **Invitation System**: Secure email-based invitations with time-limited links
- **Permission Control**: Granular permissions for external users (read, download, upload)
- **Secure Authentication**: Separate login flows for internal and external users
- **Account Creation**: Automated account setup through invitation acceptance

### External User Collaboration
- **Cross-Company Sharing**: Invite users from partner organizations
- **Secure Invitation Flow**: Email invitations with secure acceptance links
- **Time-Limited Invitations**: 7 days for internal users, 30 days for external users
- **Permission Management**: Configure specific access rights per external user
- **Company Identification**: Track external users by their company affiliation
- **Welcome Notifications**: Automated welcome emails with login credentials

### Dashboard Features
- **Interactive KPI Cards**: Click to explore detailed metrics
- **Recent Activity Tracking**: Monitor file uploads and user activity
- **Collaborator Management**: View and manage both internal and external users
- **Drop Analytics**: File counts, storage usage, and distribution
- **Quick Actions**: Create drops, invite users, export data
- **External User Tracking**: Monitor external collaborator access and activity

### Security
- **AWS IAM Integration**: Role-based access control
- **Tenant Isolation**: Complete data separation between organizations
- **Secure File Storage**: AWS S3 with proper access controls
- **Session Management**: Secure user authentication for both user types
- **Permission Enforcement**: Granular access control for external users
- **Secure Invitations**: Cryptographically secure invitation tokens

## 🏗️ Architecture

### Tech Stack
- **Backend**: Python Flask
- **Database**: AWS DynamoDB
- **File Storage**: AWS S3
- **Infrastructure**: AWS CDK (Cloud Development Kit)
- **Email Service**: AWS SES for invitation delivery
- **Frontend**: HTML/CSS/JavaScript with Tailwind CSS
- **File Transfer**: AWS Transfer Family (SFTP)

### AWS Services Used
- **DynamoDB**: User and drop metadata storage, invitation management
- **S3**: Secure file storage
- **Transfer Family**: SFTP server for file uploads
- **SES**: Email delivery for invitations and notifications
- **IAM**: Access control and permissions
- **CloudFormation**: Infrastructure as Code

## 📦 Installation

### Prerequisites
- Python 3.11+
- AWS CLI configured
- Node.js (for AWS CDK)
- AWS CDK CLI installed

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ftpme
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your AWS configuration
   ```

5. **Deploy AWS infrastructure**
   ```bash
   cdk deploy
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

## 🎯 Usage

### Creating a Drop
1. Navigate to the dashboard
2. Click "Create Drop" or use the quick action in any modal
3. Provide a name, purpose, and select a color
4. The drop is created with appropriate S3 folder structure

### Inviting External Users
1. Navigate to a drop's settings or use the dashboard
2. Click "Invite External User"
3. Enter the user's email and company name
4. Select the drops to share and set permissions
5. The user receives a secure invitation email
6. They create their account through the invitation link

### Managing Users
1. Click on the "Collaborators" KPI card
2. View current users and their drop participation
3. Manage both internal and external user access
4. Monitor external user activity and permissions

### File Management
1. Click on any drop to view its files
2. Navigate through folders using the breadcrumb interface
3. Upload files via SFTP using provided credentials
4. External users see only files they have permission to access

### Dashboard Analytics
- **Active Drops**: View all drops with file counts and member information
- **Recent Activity**: Track recent uploads and user activity
- **Files Shared**: Analyze file distribution across drops
- **Collaborators**: Manage user access and permissions for internal and external users
- **External User Metrics**: Monitor cross-company collaboration activity

## 🔧 Configuration

### Environment Variables
```bash
# AWS Configuration
AWS_REGION=us-east-2
S3_BUCKET_NAME=your-bucket-name
TENANT_TABLE_NAME=your-dynamodb-table

# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key
```

### AWS CDK Configuration
The infrastructure is defined in `file_exchange/platform_stack.py` and includes:
- DynamoDB table for tenant data
- S3 bucket for file storage
- IAM roles and policies
- Transfer Family SFTP server

## 🚀 Deployment

### Development
```bash
python app.py
```
Access at `http://localhost:5001`

### Production
1. Update environment variables for production
2. Deploy infrastructure: `cdk deploy --profile production`
3. Deploy application to your preferred hosting service
4. Configure domain and SSL certificates

## 📁 Project Structure

```
ftpme/
├── app.py                 # Main Flask application
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── dashboard.html    # Main dashboard
│   ├── drops_dashboard.html # Interactive drops dashboard
│   └── ...
├── file_exchange/         # AWS CDK infrastructure
│   └── platform_stack.py # Infrastructure definition
├── uploads/              # Local file uploads (development)
├── cdk.json              # CDK configuration
└── requirements.txt      # Python dependencies
```

## 🔐 Security Considerations

- All file access is controlled through AWS IAM roles
- Tenant data is completely isolated in DynamoDB
- S3 buckets use proper access policies
- Session management with secure cookies
- SFTP access with individual user credentials
- **External User Isolation**: External users can only access specifically shared drops
- **Invitation Security**: Time-limited, cryptographically secure invitation tokens
- **Permission Enforcement**: Granular access control prevents unauthorized file access
- **Company Segregation**: External users are isolated by company affiliation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation in the `docs/` folder
- Review AWS CloudFormation logs for infrastructure issues

## 🔄 Recent Updates

- ✅ Interactive dashboard with clickable KPI cards
- ✅ Comprehensive modals for drops, users, files, and activity
- ✅ Real-time file counting and storage analytics
- ✅ Improved user management with accurate data display
- ✅ Enhanced UI with hover effects and smooth transitions
- ✅ **External User Invitation System**: Complete workflow for inviting external collaborators
- ✅ **Cross-Company File Sharing**: Secure sharing with partners, clients, and vendors
- ✅ **Automated Email Notifications**: Invitation and welcome email system
- ✅ **Granular Permission Control**: Configurable access rights for external users
- ✅ **AWS Region Consolidation**: Migrated all services to us-east-2 region 