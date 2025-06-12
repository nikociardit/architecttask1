#!/usr/bin/env python3
"""
Complete API Test Script
Tests all backend endpoints to ensure they work correctly
"""

import requests
import json
import time
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api"

class APITester:
    def __init__(self):
        self.session = requests.Session()
        self.access_token = None
        self.test_results = []
    
    def test_endpoint(self, method, url, data=None, headers=None, expected_status=200, description=""):
        """Test a single API endpoint"""
        
        try:
            response = self.session.request(method, url, json=data, headers=headers)
            
            success = response.status_code == expected_status
            result = {
                "description": description,
                "method": method,
                "url": url,
                "expected_status": expected_status,
                "actual_status": response.status_code,
                "success": success,
                "response_data": response.json() if response.headers.get("content-type", "").startswith("application/json") else None,
                "timestamp": datetime.now().isoformat()
            }
            
            self.test_results.append(result)
            
            status_icon = "[OK]" if success else "[ERROR]"
            logger.info(f"{status_icon} {description} - {method} {url} -> {response.status_code}")
            
            if not success:
                logger.error(f"  Expected: {expected_status}, Got: {response.status_code}")
                if response.text:
                    logger.error(f"  Response: {response.text[:200]}")
            
            return response
            
        except Exception as e:
            logger.error(f"[ERROR] {description} - Exception: {e}")
            self.test_results.append({
                "description": description,
                "method": method,
                "url": url,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            return None
    
    def set_auth_header(self):
        """Set authentication header for subsequent requests"""
        if self.access_token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })
    
    def test_health_endpoints(self):
        """Test basic health and info endpoints"""
        logger.info("Testing health endpoints...")
        
        # Root endpoint
        self.test_endpoint("GET", BASE_URL, description="Root endpoint")
        
        # Health check
        self.test_endpoint("GET", f"{API_BASE}/health", description="Health check")
        
        # Test database connectivity
        self.test_endpoint("GET", f"{API_BASE}/test-db", description="Database connectivity")
    
    def test_authentication(self):
        """Test authentication endpoints"""
        logger.info("Testing authentication...")
        
        # Test login with correct credentials
        login_data = {
            "username": "admin",
            "password": "ChangeMe123!"
        }
        
        response = self.test_endpoint(
            "POST", 
            f"{API_BASE}/auth/login",
            data=login_data,
            description="Admin login"
        )
        
        if response and response.status_code == 200:
            data = response.json()
            self.access_token = data.get("access_token")
            logger.info(f"  Got access token: {self.access_token[:20]}...")
            self.set_auth_header()
        
        # Test login with wrong credentials
        wrong_login = {
            "username": "admin",
            "password": "wrongpassword"
        }
        
        self.test_endpoint(
            "POST",
            f"{API_BASE}/auth/login",
            data=wrong_login,
            expected_status=401,
            description="Login with wrong password"
        )
        
        # Test token validation
        if self.access_token:
            self.test_endpoint(
                "GET",
                f"{API_BASE}/auth/validate",
                description="Token validation"
            )
            
            # Test getting current user info
            self.test_endpoint(
                "GET",
                f"{API_BASE}/auth/me",
                description="Get current user info"
            )
    
    def test_user_management(self):
        """Test user management endpoints"""
        logger.info("Testing user management...")
        
        if not self.access_token:
            logger.error("No access token available for user tests")
            return
        
        # List users
        self.test_endpoint(
            "GET",
            f"{API_BASE}/users/",
            description="List users"
        )
        
        # Get user stats
        self.test_endpoint(
            "GET",
            f"{API_BASE}/users/stats/summary",
            description="User statistics"
        )
        
        # Create test user
        test_user = {
            "username": "testuser",
            "email": "test@example.com",
            "full_name": "Test User",
            "role": "technician",
            "password": "TestPassword123!"
        }
        
        response = self.test_endpoint(
            "POST",
            f"{API_BASE}/users/",
            data=test_user,
            expected_status=200,
            description="Create test user"
        )
        
        test_user_id = None
        if response and response.status_code == 200:
            test_user_id = response.json().get("id")
            logger.info(f"  Created test user with ID: {test_user_id}")
        
        # Get specific user
        if test_user_id:
            self.test_endpoint(
                "GET",
                f"{API_BASE}/users/{test_user_id}",
                description="Get specific user"
            )
            
            # Update user
            update_data = {
                "full_name": "Updated Test User"
            }
            
            self.test_endpoint(
                "PUT",
                f"{API_BASE}/users/{test_user_id}",
                data=update_data,
                description="Update user"
            )
            
            # Delete user (soft delete)
            self.test_endpoint(
                "DELETE",
                f"{API_BASE}/users/{test_user_id}",
                description="Delete test user"
            )
    
    def test_client_management(self):
        """Test client management endpoints"""
        logger.info("Testing client management...")
        
        # List clients
        self.test_endpoint(
            "GET",
            f"{API_BASE}/clients/",
            description="List clients"
        )
        
        # Get client stats
        self.test_endpoint(
            "GET",
            f"{API_BASE}/clients/stats/summary",
            description="Client statistics"
        )
        
        # Register test client
        test_client = {
            "client_id": "test-client-001",
            "hostname": "test-workstation",
            "os_version": "Windows 11",
            "architecture": "x64",
            "client_version": "1.0.0"
        }
        
        response = self.test_endpoint(
            "POST",
            f"{API_BASE}/clients/register",
            data=test_client,
            description="Register test client"
        )
        
        if response and response.status_code == 200:
            client_data = response.json()
            client_db_id = client_data.get("id")
            
            # Test heartbeat
            heartbeat_data = {
                "client_id": "test-client-001",
                "ip_address": "192.168.1.100",
                "vpn_connected": False,
                "uptime": 3600
            }
            
            self.test_endpoint(
                "POST",
                f"{API_BASE}/clients/test-client-001/heartbeat",
                data=heartbeat_data,
                description="Client heartbeat"
            )
            
            # Get client config
            self.test_endpoint(
                "GET",
                f"{API_BASE}/clients/test-client-001/config",
                description="Get client config"
            )
            
            # Get specific client
            if client_db_id:
                self.test_endpoint(
                    "GET",
                    f"{API_BASE}/clients/{client_db_id}",
                    description="Get specific client"
                )
    
    def test_task_management(self):
        """Test task management endpoints"""
        logger.info("Testing task management...")
        
        if not self.access_token:
            logger.error("No access token available for task tests")
            return
        
        # List tasks
        self.test_endpoint(
            "GET",
            f"{API_BASE}/tasks/",
            description="List tasks"
        )
        
        # Get task stats
        self.test_endpoint(
            "GET",
            f"{API_BASE}/tasks/stats/summary",
            description="Task statistics"
        )
        
        # First, we need a client to assign tasks to
        # This assumes we have at least one client from previous tests
        
        # Create test task
        test_task = {
            "name": "Test Task",
            "description": "A test task for API validation",
            "task_type": "powershell",
            "command": "Get-Date",
            "timeout_seconds": 60,
            "client_id": 1,  # Assuming client ID 1 exists
            "run_as_admin": False
        }
        
        response = self.test_endpoint(
            "POST",
            f"{API_BASE}/tasks/",
            data=test_task,
            description="Create test task"
        )
        
        if response and response.status_code == 200:
            task_data = response.json()
            task_id = task_data.get("id")
            task_uuid = task_data.get("task_id")
            
            if task_id:
                # Get specific task
                self.test_endpoint(
                    "GET",
                    f"{API_BASE}/tasks/{task_id}",
                    description="Get specific task"
                )
                
                # Cancel task
                self.test_endpoint(
                    "POST",
                    f"{API_BASE}/tasks/{task_id}/cancel",
                    description="Cancel task"
                )
        
        # Test getting pending tasks for client
        self.test_endpoint(
            "GET",
            f"{API_BASE}/tasks/client/test-client-001/pending",
            description="Get pending tasks for client"
        )
    
    def test_audit_logs(self):
        """Test audit log endpoints"""
        logger.info("Testing audit logs...")
        
        if not self.access_token:
            logger.error("No access token available for audit tests")
            return
        
        # List audit logs
        self.test_endpoint(
            "GET",
            f"{API_BASE}/audit/",
            description="List audit logs"
        )
        
        # Get audit stats
        self.test_endpoint(
            "GET",
            f"{API_BASE}/audit/stats/summary",
            description="Audit statistics"
        )
        
        # Get available actions
        self.test_endpoint(
            "GET",
            f"{API_BASE}/audit/actions/available",
            description="Available audit actions"
        )
        
        # Get security alerts
        self.test_endpoint(
            "GET",
            f"{API_BASE}/audit/security/alerts",
            description="Security alerts"
        )
    
    def run_all_tests(self):
        """Run all API tests"""
        logger.info("Starting comprehensive API tests...")
        start_time = time.time()
        
        # Run test suites in order
        self.test_health_endpoints()
        self.test_authentication()
        self.test_user_management()
        self.test_client_management()
        self.test_task_management()
        self.test_audit_logs()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Summary
        total_tests = len(self.test_results)
        successful_tests = len([r for r in self.test_results if r.get("success", False)])
        failed_tests = total_tests - successful_tests
        
        logger.info(f"\n{'='*60}")
        logger.info(f"API TEST SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total tests: {total_tests}")
        logger.info(f"Successful: {successful_tests}")
        logger.info(f"Failed: {failed_tests}")
        logger.info(f"Duration: {duration:.2f} seconds")
        logger.info(f"Success rate: {(successful_tests/total_tests*100):.1f}%")
        
        if failed_tests > 0:
            logger.info(f"\nFailed tests:")
            for result in self.test_results:
                if not result.get("success", False):
                    logger.info(f"  - {result['description']}")
        
        return successful_tests == total_tests

def main():
    """Main function"""
    tester = APITester()
    
    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code != 200:
            logger.error("Backend server is not responding correctly")
            return False
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to backend server. Make sure it's running on localhost:8000")
        return False
    
    # Run tests
    return tester.run_all_tests()

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)