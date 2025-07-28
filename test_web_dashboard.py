#!/usr/bin/env python3
"""
Test script for Cowrie Web Dashboard

This script tests the web dashboard functionality by:
1. Creating a test configuration
2. Starting the web dashboard output module
3. Sending test events
4. Testing API endpoints
5. Verifying export functionality

Usage:
    python test_web_dashboard.py
"""

import json
import os
import sys
import time
import tempfile
import requests
from datetime import datetime
from pathlib import Path

# Add Cowrie source to path
sys.path.insert(0, 'src')

try:
    from cowrie.core.config import readConfigFile
    from cowrie.output.webdashboard import Output as WebDashboardOutput
    from cowrie.output.jsonexport import Output as JSONExportOutput
    from cowrie.output.sqlexport import Output as SQLExportOutput
except ImportError as e:
    print(f"Error importing Cowrie modules: {e}")
    print("Make sure you're running this from the Cowrie root directory")
    sys.exit(1)


class TestWebDashboard:
    """Test class for web dashboard functionality"""
    
    def __init__(self):
        self.test_dir = tempfile.mkdtemp(prefix="cowrie_test_")
        self.config_file = os.path.join(self.test_dir, "test_cowrie.cfg")
        self.dashboard_output = None
        self.json_export_output = None
        self.sql_export_output = None
        self.base_url = "http://localhost:8081"
        
        print(f"Test directory: {self.test_dir}")
    
    def create_test_config(self):
        """Create a test configuration file"""
        config_content = f"""
[honeypot]
log_path = {self.test_dir}
state_path = {self.test_dir}

[output_webdashboard]
enabled = true
port = 8081
host = 127.0.0.1
debug = true
max_events = 100

[output_jsonexport]
enabled = true
export_dir = {self.test_dir}/exports
compress = false
include_metadata = true
max_buffer_size = 50

[output_sqlexport]
enabled = true
database_type = sqlite
export_dir = {self.test_dir}/sql_exports
sqlite_file = {self.test_dir}/test_cowrie.db
"""
        
        with open(self.config_file, 'w') as f:
            f.write(config_content)
        
        # Set the config file for Cowrie
        os.environ['COWRIE_CONFIG'] = self.config_file

        # Reload config
        import cowrie.core.config
        cowrie.core.config.CowrieConfig = readConfigFile(self.config_file)
        
        print(f"Created test config: {self.config_file}")
    
    def start_outputs(self):
        """Start the output modules"""
        try:
            # Start web dashboard
            self.dashboard_output = WebDashboardOutput()
            self.dashboard_output.start()
            print("✓ Web dashboard started")
            
            # Start JSON export
            self.json_export_output = JSONExportOutput()
            self.json_export_output.start()
            print("✓ JSON export started")
            
            # Start SQL export
            self.sql_export_output = SQLExportOutput()
            self.sql_export_output.start()
            print("✓ SQL export started")
            
            # Wait a moment for servers to start
            time.sleep(2)
            
        except Exception as e:
            print(f"✗ Error starting outputs: {e}")
            raise
    
    def generate_test_events(self):
        """Generate test events"""
        test_events = [
            {
                'eventid': 'cowrie.session.connect',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100',
                'src_port': 12345,
                'dst_ip': '10.0.0.1',
                'dst_port': 22,
                'sensor': 'test_sensor',
                'version': 'SSH-2.0-OpenSSH_7.4'
            },
            {
                'eventid': 'cowrie.login.failed',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'username': 'admin',
                'password': 'password123',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.login.success',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'username': 'root',
                'password': 'toor',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'input': 'ls -la',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'input': 'cat /etc/passwd',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.session.closed',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100'
            }
        ]
        
        print(f"Generating {len(test_events)} test events...")
        
        for event in test_events:
            if self.dashboard_output:
                self.dashboard_output.write(event)
            if self.json_export_output:
                self.json_export_output.write(event)
            if self.sql_export_output:
                self.sql_export_output.write(event)
            time.sleep(0.1)  # Small delay between events
        
        print("✓ Test events generated")
    
    def test_web_interface(self):
        """Test the web interface"""
        try:
            # Test main dashboard page
            response = requests.get(self.base_url, timeout=5)
            if response.status_code == 200:
                print("✓ Web dashboard accessible")
                if "Cowrie Honeypot Dashboard" in response.text:
                    print("✓ Dashboard content loaded correctly")
                else:
                    print("✗ Dashboard content not found")
            else:
                print(f"✗ Web dashboard returned status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print(f"✗ Error accessing web dashboard: {e}")
    
    def test_api_endpoints(self):
        """Test API endpoints"""
        try:
            # Test events endpoint
            response = requests.get(f"{self.base_url}/api/events", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and len(data.get('events', [])) > 0:
                    print(f"✓ Events API working ({len(data['events'])} events)")
                else:
                    print("✗ Events API returned no events")
            else:
                print(f"✗ Events API returned status {response.status_code}")
            
            # Test stats endpoint
            response = requests.get(f"{self.base_url}/api/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('stats'):
                    print(f"✓ Stats API working (total events: {data['stats'].get('total_events', 0)})")
                else:
                    print("✗ Stats API returned no data")
            else:
                print(f"✗ Stats API returned status {response.status_code}")
            
            # Test JSON export endpoint
            response = requests.get(f"{self.base_url}/api/export?format=json", timeout=5)
            if response.status_code == 200:
                print("✓ JSON export API working")
            else:
                print(f"✗ JSON export API returned status {response.status_code}")
            
            # Test SQL export endpoint
            response = requests.get(f"{self.base_url}/api/export?format=sql", timeout=5)
            if response.status_code == 200:
                print("✓ SQL export API working")
            else:
                print(f"✗ SQL export API returned status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print(f"✗ Error testing API endpoints: {e}")
    
    def test_export_files(self):
        """Test export file generation"""
        try:
            # Check JSON export files
            exports_dir = os.path.join(self.test_dir, "exports")
            if os.path.exists(exports_dir):
                json_files = [f for f in os.listdir(exports_dir) if f.endswith('.json')]
                if json_files:
                    print(f"✓ JSON export files created ({len(json_files)} files)")
                else:
                    print("✗ No JSON export files found")
            else:
                print("✗ JSON exports directory not found")
            
            # Check SQL export files
            sql_exports_dir = os.path.join(self.test_dir, "sql_exports")
            if os.path.exists(sql_exports_dir):
                sql_files = [f for f in os.listdir(sql_exports_dir) if f.endswith('.sql')]
                if sql_files:
                    print(f"✓ SQL export files created ({len(sql_files)} files)")
                else:
                    print("✗ No SQL export files found")
            else:
                print("✗ SQL exports directory not found")
            
            # Check SQLite database
            db_file = os.path.join(self.test_dir, "test_cowrie.db")
            if os.path.exists(db_file):
                print("✓ SQLite database created")
            else:
                print("✗ SQLite database not found")
        
        except Exception as e:
            print(f"✗ Error checking export files: {e}")
    
    def stop_outputs(self):
        """Stop the output modules"""
        try:
            if self.dashboard_output:
                self.dashboard_output.stop()
                print("✓ Web dashboard stopped")
            
            if self.json_export_output:
                self.json_export_output.stop()
                print("✓ JSON export stopped")
            
            if self.sql_export_output:
                self.sql_export_output.stop()
                print("✓ SQL export stopped")
        
        except Exception as e:
            print(f"✗ Error stopping outputs: {e}")
    
    def cleanup(self):
        """Clean up test files"""
        import shutil
        try:
            shutil.rmtree(self.test_dir)
            print(f"✓ Cleaned up test directory: {self.test_dir}")
        except Exception as e:
            print(f"✗ Error cleaning up: {e}")
    
    def run_tests(self):
        """Run all tests"""
        print("=" * 60)
        print("Cowrie Web Dashboard Test Suite")
        print("=" * 60)
        
        try:
            print("\n1. Setting up test environment...")
            self.create_test_config()
            
            print("\n2. Starting output modules...")
            self.start_outputs()
            
            print("\n3. Generating test events...")
            self.generate_test_events()
            
            print("\n4. Testing web interface...")
            self.test_web_interface()
            
            print("\n5. Testing API endpoints...")
            self.test_api_endpoints()
            
            print("\n6. Testing export files...")
            self.test_export_files()
            
            print("\n" + "=" * 60)
            print("Test completed! Check the results above.")
            print(f"Web dashboard should be accessible at: {self.base_url}")
            print("Press Ctrl+C to stop the test and clean up.")
            print("=" * 60)
            
            # Keep running for manual testing
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping test...")
        
        finally:
            print("\n7. Stopping output modules...")
            self.stop_outputs()
            
            print("\n8. Cleaning up...")
            self.cleanup()


if __name__ == "__main__":
    test = TestWebDashboard()
    test.run_tests()
