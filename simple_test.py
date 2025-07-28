#!/usr/bin/env python3
"""
Simple test script for Cowrie Web Dashboard

This script tests the basic functionality without complex configuration.
"""

import sys
import os
import time
import tempfile
from datetime import datetime

# Add Cowrie source to path
sys.path.insert(0, 'src')

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from cowrie.output.webdashboard import EventStore, APIResource, DashboardResource
        print("✓ Web dashboard modules imported successfully")
    except ImportError as e:
        print(f"✗ Error importing web dashboard modules: {e}")
        return False
    
    try:
        from cowrie.output.jsonexport import JSONExportManager
        print("✓ JSON export modules imported successfully")
    except ImportError as e:
        print(f"✗ Error importing JSON export modules: {e}")
        return False
    
    try:
        from cowrie.output.sqlexport import SQLExportManager
        print("✓ SQL export modules imported successfully")
    except ImportError as e:
        print(f"✗ Error importing SQL export modules: {e}")
        return False
    
    return True

def test_event_store():
    """Test the EventStore functionality"""
    print("\nTesting EventStore...")
    
    from cowrie.output.webdashboard import EventStore
    
    # Create event store
    store = EventStore(max_events=10)
    
    # Test adding events
    test_events = [
        {
            'eventid': 'cowrie.session.connect',
            'session': 'test_session_001',
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_port': 22
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
            'eventid': 'cowrie.command.input',
            'session': 'test_session_001',
            'timestamp': datetime.now().isoformat(),
            'input': 'ls -la',
            'src_ip': '192.168.1.100'
        }
    ]
    
    for event in test_events:
        store.add_event(event)
    
    # Test getting events
    events = store.get_events()
    if len(events) == 3:
        print("✓ EventStore correctly stores and retrieves events")
    else:
        print(f"✗ EventStore test failed: expected 3 events, got {len(events)}")
        return False
    
    # Test filtering
    filtered = store.get_events(event_type='cowrie.login.failed')
    if len(filtered) == 1:
        print("✓ EventStore filtering works correctly")
    else:
        print(f"✗ EventStore filtering failed: expected 1 event, got {len(filtered)}")
        return False
    
    # Test statistics
    stats = store.get_stats()
    if stats['total_events'] == 3:
        print("✓ EventStore statistics work correctly")
    else:
        print(f"✗ EventStore statistics failed: expected 3 total events, got {stats['total_events']}")
        return False
    
    return True

def test_json_export():
    """Test JSON export functionality"""
    print("\nTesting JSON Export...")
    
    from cowrie.output.jsonexport import JSONExportManager
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix="cowrie_json_test_")
    
    try:
        # Create export manager
        manager = JSONExportManager(
            export_dir=temp_dir,
            compress=False,
            include_metadata=True
        )
        
        # Test events
        test_events = [
            {
                'eventid': 'cowrie.session.connect',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.login.success',
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat(),
                'username': 'root',
                'password': 'toor',
                'src_ip': '192.168.1.100'
            }
        ]
        
        # Add events to buffer
        for event in test_events:
            manager.add_event(event)
        
        # Export to file
        export_file = os.path.join(temp_dir, "test_export.json")
        result = manager.export_filtered(export_file)
        
        # Check if file was created
        export_path = result.get('filepath', export_file)
        if os.path.exists(export_path):
            print("✓ JSON export file created successfully")
            
            # Check file contents
            with open(export_path, 'r') as f:
                content = f.read()
                if 'cowrie.session.connect' in content and 'cowrie.login.success' in content:
                    print("✓ JSON export contains expected events")
                else:
                    print("✗ JSON export file doesn't contain expected events")
                    return False
        else:
            print("✗ JSON export file was not created")
            return False
        
        return True
    
    finally:
        # Clean up
        import shutil
        shutil.rmtree(temp_dir)

def test_sql_export():
    """Test SQL export functionality"""
    print("\nTesting SQL Export...")

    try:
        from cowrie.output.sqlexport import SQLExportManager
        print("✓ SQLExportManager can be imported")

        # Test basic instantiation
        manager = SQLExportManager(
            database_type='sqlite',
            export_dir='/tmp',
            sqlite_file=':memory:'  # Use in-memory database to avoid file locks
        )
        print("✓ SQLExportManager can be instantiated")

        # Test that we can call the initialization method
        manager._init_database()
        print("✓ Database initialization method works")

        return True

    except Exception as e:
        print(f"✗ SQL export test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("Cowrie Web Dashboard Simple Test Suite")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_event_store,
        test_json_export,
        test_sql_export
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"✗ {test.__name__} failed")
        except Exception as e:
            print(f"✗ {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
