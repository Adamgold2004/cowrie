#!/usr/bin/env python3
"""
Complete Cowrie Web Dashboard - Production Ready

This script starts the Cowrie Web Dashboard with all features:
- Real-time event viewing
- REST API endpoints
- Export functionality
- Live statistics
"""

import sys
import os
import time
from datetime import datetime

# Add Cowrie source to path
sys.path.insert(0, 'src')

def main():
    print("🚀 Starting Cowrie Web Dashboard...")
    print("="*60)
    
    # Set up environment
    os.environ['PYTHONPATH'] = 'src'
    
    try:
        # Import required modules
        from twisted.internet import reactor
        from twisted.web import server
        from twisted.web.resource import Resource
        from cowrie.output.webdashboard import EventStore, APIResource, DashboardResource
        
        print("✓ Modules imported successfully")
        
        # Create event store with sample data for demonstration
        event_store = EventStore(max_events=1000)
        
        # Add comprehensive sample events
        sample_events = [
            {
                'eventid': 'cowrie.session.connect',
                'session': 'demo_001',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100',
                'dst_port': 22,
                'protocol': 'ssh'
            },
            {
                'eventid': 'cowrie.login.failed',
                'session': 'demo_001',
                'timestamp': datetime.now().isoformat(),
                'username': 'admin',
                'password': 'password123',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.login.success',
                'session': 'demo_002',
                'timestamp': datetime.now().isoformat(),
                'username': 'root',
                'password': 'toor',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'demo_002',
                'timestamp': datetime.now().isoformat(),
                'input': 'ls -la',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.command.input',
                'session': 'demo_002',
                'timestamp': datetime.now().isoformat(),
                'input': 'cat /etc/passwd',
                'src_ip': '192.168.1.101'
            },
            {
                'eventid': 'cowrie.download',
                'session': 'demo_003',
                'timestamp': datetime.now().isoformat(),
                'url': 'http://malicious.example.com/malware.sh',
                'outfile': 'malware.sh',
                'src_ip': '192.168.1.102'
            },
            {
                'eventid': 'cowrie.session.closed',
                'session': 'demo_002',
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.101'
            }
        ]
        
        for event in sample_events:
            event_store.add_event(event)
        
        print(f"✓ Added {len(sample_events)} sample events")
        
        # Create web resources with proper mounting
        root = Resource()
        
        # Mount dashboard at root
        dashboard_resource = DashboardResource()
        root.putChild(b"", dashboard_resource)
        
        # Create API resource and mount endpoints individually
        api_resource = APIResource(event_store)
        
        # Create API container
        api_container = Resource()
        api_container.putChild(b"events", api_resource)
        api_container.putChild(b"stats", api_resource)
        api_container.putChild(b"export", api_resource)
        
        # Mount API container
        root.putChild(b"api", api_container)
        
        print("✓ Web resources configured")
        
        # Start web server
        port = 8080
        host = "127.0.0.1"
        site = server.Site(root)
        
        try:
            reactor.listenTCP(port, site, interface=host)
            print(f"✓ Web server started on http://{host}:{port}")
            
            print("\n" + "="*60)
            print("🎉 COWRIE WEB DASHBOARD IS RUNNING!")
            print("="*60)
            print(f"📊 Dashboard:     http://{host}:{port}")
            print(f"🔗 API Endpoints:")
            print(f"   • Events:      http://{host}:{port}/api/events")
            print(f"   • Statistics:  http://{host}:{port}/api/stats")
            print(f"   • Export JSON: http://{host}:{port}/api/export?format=json")
            print(f"   • Export SQL:  http://{host}:{port}/api/export?format=sql")
            print("="*60)
            print("📈 Features Available:")
            print("   • Real-time event monitoring")
            print("   • Event filtering and search")
            print("   • Live statistics dashboard")
            print("   • JSON/SQL export functionality")
            print("   • REST API for integration")
            print("="*60)
            print("🔧 Controls:")
            print("   • Press Ctrl+C to stop the server")
            print("   • Refresh browser to see new events")
            print("   • Use API endpoints for programmatic access")
            print("="*60)
            
            # Add periodic demo events
            def add_demo_event():
                import random
                
                event_types = [
                    {
                        'eventid': 'cowrie.session.connect',
                        'session': f'demo_{int(time.time())}',
                        'src_ip': f'192.168.1.{100 + random.randint(0, 50)}',
                        'dst_port': 22,
                        'protocol': 'ssh'
                    },
                    {
                        'eventid': 'cowrie.login.failed',
                        'session': f'demo_{int(time.time())}',
                        'username': random.choice(['admin', 'root', 'user', 'test']),
                        'password': random.choice(['password', '123456', 'admin', 'root']),
                        'src_ip': f'192.168.1.{100 + random.randint(0, 50)}'
                    },
                    {
                        'eventid': 'cowrie.command.input',
                        'session': f'demo_{int(time.time())}',
                        'input': random.choice(['ls -la', 'cat /etc/passwd', 'whoami', 'ps aux']),
                        'src_ip': f'192.168.1.{100 + random.randint(0, 50)}'
                    }
                ]
                
                event_template = random.choice(event_types)
                event_template['timestamp'] = datetime.now().isoformat()
                
                event_store.add_event(event_template)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Added demo event: {event_template['eventid']} from {event_template['src_ip']}")
                
                # Schedule next event (every 15 seconds)
                reactor.callLater(15, add_demo_event)
            
            # Start adding demo events after 10 seconds
            reactor.callLater(10, add_demo_event)
            
            # Start the reactor
            reactor.run()
            
        except Exception as e:
            print(f"✗ Error starting web server: {e}")
            return 1
            
    except ImportError as e:
        print(f"✗ Error importing modules: {e}")
        print("Make sure you're running this from the Cowrie root directory")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Cowrie Web Dashboard stopped by user")
        print("Thank you for using Cowrie Web Dashboard! 👋")
        sys.exit(0)
