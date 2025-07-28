#!/usr/bin/env python3
"""
Simple test to verify API resource works
"""

import sys
import os
from datetime import datetime

# Add Cowrie source to path
sys.path.insert(0, 'src')

def main():
    print("Testing API Resource directly...")
    
    try:
        from twisted.internet import reactor
        from twisted.web import server
        from twisted.web.resource import Resource
        from cowrie.output.webdashboard import EventStore, APIResource
        
        # Create event store with test data
        event_store = EventStore(max_events=100)
        
        # Add test event
        test_event = {
            'eventid': 'cowrie.session.connect',
            'session': 'test_session',
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_port': 22
        }
        event_store.add_event(test_event)
        
        print(f"✓ Event store created with {len(list(event_store.events))} events")
        
        # Create API resource directly (not mounted under /api)
        api_resource = APIResource(event_store)
        
        # Create root and mount API directly
        root = Resource()
        root.putChild(b"events", api_resource)  # Mount directly as /events
        root.putChild(b"stats", api_resource)   # Mount directly as /stats
        
        print("✓ API resource mounted directly")
        
        # Start server
        port = 8081
        site = server.Site(root)
        reactor.listenTCP(port, site, interface="127.0.0.1")
        
        print(f"✓ Server started on http://127.0.0.1:{port}")
        print("Test URLs:")
        print(f"  - http://127.0.0.1:{port}/events")
        print(f"  - http://127.0.0.1:{port}/stats")
        print("Press Ctrl+C to stop")
        
        reactor.run()
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        sys.exit(0)
