import unittest
import os
import tempfile
from app import app
from create_tenant import TenantManager
from manage_users import UserManager

class TestFileExchangePlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary directory for test files
        cls.test_dir = tempfile.mkdtemp()
        
        # Generate test SSH key
        os.system(f'ssh-keygen -t rsa -b 2048 -f {cls.test_dir}/test_key -N ""')
        
        # Initialize test data
        cls.company_name = "Test Company"
        cls.admin_email = "test@example.com"
        cls.admin_username = "testadmin"
        cls.ssh_key_path = f"{cls.test_dir}/test_key.pub"
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_home_page(self):
        """Test that the home page loads"""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'File Exchange Platform', response.data)
    
    def test_signup_page(self):
        """Test that the signup page loads"""
        response = self.app.get('/signup')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Create Your Organization', response.data)
    
    def test_tenant_creation(self):
        """Test tenant creation functionality"""
        # Read SSH key
        with open(self.ssh_key_path, 'r') as f:
            ssh_key = f.read().strip()
        
        # Create tenant
        manager = TenantManager()
        result = manager.create_tenant(
            company_name=self.company_name,
            admin_email=self.admin_email,
            admin_username=self.admin_username,
            admin_ssh_key=ssh_key
        )
        
        # Verify result
        self.assertIn('tenant_id', result)
        self.assertIn('admin_username', result)
        self.assertEqual(result['admin_username'], self.admin_username)
        
        # Store tenant_id for later tests
        self.tenant_id = result['tenant_id']
    
    def test_user_management(self):
        """Test user management functionality"""
        # Create user manager
        user_manager = UserManager(self.tenant_id)
        
        # Create test user
        test_username = "testuser"
        test_email = "testuser@example.com"
        
        with open(self.ssh_key_path, 'r') as f:
            ssh_key = f.read().strip()
        
        result = user_manager.create_user(
            username=test_username,
            email=test_email,
            ssh_key=ssh_key
        )
        
        # Verify user creation
        self.assertEqual(result['username'], test_username)
        
        # List users
        users = user_manager.list_users()
        self.assertTrue(any(user['username'] == test_username for user in users))
        
        # Delete user
        user_manager.delete_user(test_username)
        
        # Verify deletion
        users = user_manager.list_users()
        self.assertFalse(any(user['username'] == test_username for user in users))
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        import shutil
        shutil.rmtree(cls.test_dir)

if __name__ == '__main__':
    unittest.main()