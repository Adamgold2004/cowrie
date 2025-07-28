#!/usr/bin/env python3
"""
Standalone script to start just the Cowrie Web Dashboard for testing
"""

import sys
import os
import time
from datetime import datetime

# Add Cowrie source to path
sys.path.insert(0, 'src')

def main():
    print("Starting Cowrie Web Dashboard...")
    
    # Set up environment
    os.environ['PYTHONPATH'] = 'src'
    
    try:
        # Import required modules
        from twisted.internet import reactor
        from twisted.web import server
        from twisted.web.resource import Resource
        from cowrie.output.webdashboard import EventStore, APIResource, DashboardResource
        
        print("✓ Modules imported successfully")
        
        # Create event store with some test data
        event_store = EventStore(max_events=1000)
        
        # Add some sample events for demonstration
        sample_events = [
            {
                'eventid': 'cowrie.session.connect',
                'session': 'demo_session_001',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100',
                'dst_port': 22,
                'protocol': 'ssh'
            },
            {
                'eventid': 'cowrie.login.failed',
                'session': 'demo_session_001',
                'timestamp': datetime.now().isoformat(),
                'username': 'admin',
                'password': 'password123',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.login.success',
                'session': 'demo_session_002',
                'timestamp': datetime.now().isoformat(),
                'username': 'root',
                'password': 'toor',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'demo_session_002',
                'timestamp': datetime.now().isoformat(),
                'input': 'ls -la',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'demo_session_002',
                'timestamp': datetime.now().isoformat(),
                'input': 'cat /etc/passwd',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.session.closed',
                'session': 'demo_session_002',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.101'
            }
        ]
        
        for event in sample_events:
            event_store.add_event(event)
        
        print(f"✓ Added {len(sample_events)} sample events to event store")
        
        # Create web resources
        root = Resource()
        dashboard_resource = DashboardResource()
        api_resource = APIResource(event_store)

        root.putChild(b"", dashboard_resource)
        root.putChild(b"api", api_resource)

        print("✓ Web resources created")
        print(f"  - Dashboard resource: {dashboard_resource}")
        print(f"  - API resource: {api_resource}")
        print(f"  - Event store has {len(list(event_store.events))} events")
        
        # Start web server
        port = 8080
        site = server.Site(root)
        
        try:
            reactor.listenTCP(port, site, interface="127.0.0.1")
            print(f"✓ Web server started on http://127.0.0.1:{port}")
            print("\n" + "="*60)
            print("🎉 Cowrie Web Dashboard is running!")
            print("="*60)
            print(f"📊 Dashboard URL: http://127.0.0.1:{port}")
            print(f"🔗 API Endpoints:")
            print(f"   • Events: http://127.0.0.1:{port}/api/events")
            print(f"   • Stats:  http://127.0.0.1:{port}/api/stats")
            print(f"   • Export: http://127.0.0.1:{port}/api/export?format=json")
            print("="*60)
            print("Press Ctrl+C to stop the server")
            print("="*60)
            
            # Add a timer to add more events periodically for demo
            def add_demo_event():
                demo_event = {
                    'eventid': 'cowrie.session.connect',
                    'session': f'demo_session_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': f'192.168.1.{100 + (int(time.time()) % 50)}',
                    'dst_port': 22,
                    'protocol': 'ssh'
                }
                event_store.add_event(demo_event)
                print(f"Added demo event: {demo_event['eventid']} from {demo_event['src_ip']}")
                
                # Schedule next event
                reactor.callLater(10, add_demo_event)
            
            # Start adding demo events
            reactor.callLater(5, add_demo_event)
            
            # Start the reactor
            reactor.run()
            
        except Exception as e:
            print(f"✗ Error starting web server: {e}")
            return 1
            
    except ImportError as e:
        print(f"✗ Error importing modules: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        sys.exit(0)
