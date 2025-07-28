"""
Cowrie Web Dashboard Output Module

This module provides a web-based dashboard for viewing Cowrie logs in real-time
and exporting logs in JSON and SQL formats.

Configuration:
[output_webdashboard]
enabled = true
port = 8080
host = 0.0.0.0
debug = false
max_events = 1000
export_formats = json,sql
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from twisted.internet import reactor, defer
from twisted.python import log
from twisted.web import resource, server, static
from twisted.web.resource import Resource

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class EventStore:
    """Store and manage events for the web dashboard"""
    
    def __init__(self, max_events: int = 1000):
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)
        self.event_id_counter = 0
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the store"""
        self.event_id_counter += 1
        event_copy = event.copy()
        event_copy['id'] = self.event_id_counter
        event_copy['received_at'] = time.time()
        self.events.append(event_copy)
    
    def get_events(self, limit: Optional[int] = None, 
                   event_type: Optional[str] = None,
                   since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get events with optional filtering"""
        events = list(self.events)
        
        # Filter by event type
        if event_type:
            events = [e for e in events if e.get('eventid') == event_type]
        
        # Filter by time
        if since:
            events = [e for e in events if e.get('received_at', 0) >= since]
        
        # Apply limit
        if limit:
            events = events[-limit:]
        
        return events
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored events"""
        if not self.events:
            return {
                'total_events': 0,
                'event_types': {},
                'latest_event': None,
                'oldest_event': None
            }
        
        event_types = {}
        for event in self.events:
            event_type = event.get('eventid', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        return {
            'total_events': len(self.events),
            'event_types': event_types,
            'latest_event': self.events[-1].get('received_at'),
            'oldest_event': self.events[0].get('received_at')
        }


class APIResource(Resource):
    """REST API resource for the web dashboard"""
    
    def __init__(self, event_store: EventStore):
        Resource.__init__(self)
        self.event_store = event_store
    
    def render_GET(self, request):
        """Handle GET requests to the API"""
        request.setHeader(b'content-type', b'application/json')
        request.setHeader(b'access-control-allow-origin', b'*')

        # Determine endpoint from the request path
        # When mounted as /api/events, /api/stats, etc., we need to check the full path
        path = request.path.decode('utf-8')

        if '/events' in path:
            return self._handle_events_request(request)
        elif '/stats' in path:
            return self._handle_stats_request(request)
        elif '/export' in path:
            return self._handle_export_request(request)
        else:
            return self._error_response(request, f"Unknown API endpoint: {path}")
    
    def _handle_events_request(self, request) -> bytes:
        """Handle requests for events"""
        try:
            # Parse query parameters
            limit = request.args.get(b'limit')
            limit = int(limit[0]) if limit else None
            
            event_type = request.args.get(b'type')
            event_type = event_type[0].decode('utf-8') if event_type else None
            
            since = request.args.get(b'since')
            since = float(since[0]) if since else None
            
            events = self.event_store.get_events(limit=limit, event_type=event_type, since=since)
            
            return json.dumps({
                'success': True,
                'events': events,
                'count': len(events)
            }).encode('utf-8')
            
        except Exception as e:
            return self._error_response(request, f"Error retrieving events: {str(e)}")
    
    def _handle_stats_request(self, request) -> bytes:
        """Handle requests for statistics"""
        try:
            stats = self.event_store.get_stats()
            return json.dumps({
                'success': True,
                'stats': stats
            }).encode('utf-8')
        except Exception as e:
            return self._error_response(request, f"Error retrieving stats: {str(e)}")
    
    def _handle_export_request(self, request) -> bytes:
        """Handle export requests"""
        try:
            format_type = request.args.get(b'format', [b'json'])[0].decode('utf-8')
            
            if format_type == 'json':
                return self._export_json(request)
            elif format_type == 'sql':
                return self._export_sql(request)
            else:
                return self._error_response(request, f"Unsupported export format: {format_type}")
                
        except Exception as e:
            return self._error_response(request, f"Export error: {str(e)}")
    
    def _export_json(self, request) -> bytes:
        """Export events as JSON"""
        events = self.event_store.get_events()
        
        request.setHeader(b'content-type', b'application/json')
        request.setHeader(b'content-disposition', 
                         f'attachment; filename="cowrie_logs_{int(time.time())}.json"'.encode())
        
        return json.dumps({
            'export_timestamp': time.time(),
            'export_date': datetime.now().isoformat(),
            'total_events': len(events),
            'events': events
        }, indent=2).encode('utf-8')
    
    def _export_sql(self, request) -> bytes:
        """Export events as SQL INSERT statements"""
        events = self.event_store.get_events()
        
        request.setHeader(b'content-type', b'text/plain')
        request.setHeader(b'content-disposition', 
                         f'attachment; filename="cowrie_logs_{int(time.time())}.sql"'.encode())
        
        sql_lines = [
            "-- Cowrie Honeypot Log Export",
            f"-- Generated: {datetime.now().isoformat()}",
            f"-- Total Events: {len(events)}",
            "",
            "CREATE TABLE IF NOT EXISTS cowrie_events (",
            "    id INTEGER PRIMARY KEY,",
            "    eventid VARCHAR(255),",
            "    timestamp DATETIME,",
            "    session VARCHAR(255),",
            "    src_ip VARCHAR(45),",
            "    message TEXT,",
            "    data TEXT",
            ");",
            ""
        ]
        
        for event in events:
            # Escape single quotes in strings
            def escape_sql(value):
                if value is None:
                    return 'NULL'
                if isinstance(value, str):
                    return f"'{value.replace(chr(39), chr(39)+chr(39))}'"
                return str(value)
            
            sql_lines.append(
                f"INSERT INTO cowrie_events (id, eventid, timestamp, session, src_ip, message, data) "
                f"VALUES ({event.get('id', 'NULL')}, "
                f"{escape_sql(event.get('eventid'))}, "
                f"{escape_sql(event.get('timestamp'))}, "
                f"{escape_sql(event.get('session'))}, "
                f"{escape_sql(event.get('src_ip'))}, "
                f"{escape_sql(event.get('message'))}, "
                f"{escape_sql(json.dumps(event))});"
            )
        
        return '\n'.join(sql_lines).encode('utf-8')
    
    def _error_response(self, request, message: str) -> bytes:
        """Return an error response"""
        request.setResponseCode(400)
        return json.dumps({
            'success': False,
            'error': message
        }).encode('utf-8')


class DashboardResource(Resource):
    """Main dashboard HTML page"""

    def render_GET(self, request):
        """Serve the dashboard HTML page"""
        request.setHeader(b'content-type', b'text/html; charset=utf-8')

        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cowrie Honeypot Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .header p {
            opacity: 0.9;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }

        .stat-card h3 {
            color: #667eea;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }

        .controls {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }

        .controls h3 {
            margin-bottom: 1rem;
            color: #333;
        }

        .control-group {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .control-group label {
            font-weight: 500;
        }

        .control-group select,
        .control-group input,
        .control-group button {
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .control-group button {
            background: #667eea;
            color: white;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .control-group button:hover {
            background: #5a6fd8;
        }

        .export-buttons {
            display: flex;
            gap: 0.5rem;
        }

        .export-btn {
            padding: 0.5rem 1rem;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.9rem;
            transition: background-color 0.3s;
        }

        .export-btn:hover {
            background: #218838;
        }

        .export-btn.sql {
            background: #17a2b8;
        }

        .export-btn.sql:hover {
            background: #138496;
        }

        .events-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .events-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .events-header h3 {
            color: #333;
        }

        .auto-refresh {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .events-list {
            max-height: 600px;
            overflow-y: auto;
        }

        .event-item {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #f0f0f0;
            transition: background-color 0.2s;
        }

        .event-item:hover {
            background-color: #f8f9fa;
        }

        .event-item:last-child {
            border-bottom: none;
        }

        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .event-type {
            background: #667eea;
            color: white;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .event-time {
            color: #666;
            font-size: 0.9rem;
        }

        .event-details {
            color: #555;
            line-height: 1.4;
        }

        .event-session {
            color: #007bff;
            font-family: monospace;
            font-size: 0.9rem;
        }

        .loading {
            text-align: center;
            padding: 2rem;
            color: #666;
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 1rem;
            border-radius: 4px;
            margin: 1rem 0;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .control-group {
                flex-direction: column;
                align-items: stretch;
            }

            .export-buttons {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🍯 Cowrie Honeypot Dashboard</h1>
        <p>Real-time monitoring and log export for your SSH/Telnet honeypot</p>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="value" id="total-events">-</div>
            </div>
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <div class="value" id="active-sessions">-</div>
            </div>
            <div class="stat-card">
                <h3>Login Attempts</h3>
                <div class="value" id="login-attempts">-</div>
            </div>
            <div class="stat-card">
                <h3>Commands Executed</h3>
                <div class="value" id="commands-executed">-</div>
            </div>
        </div>

        <div class="controls">
            <h3>Controls & Export</h3>
            <div class="control-group">
                <label for="event-filter">Filter by Event Type:</label>
                <select id="event-filter">
                    <option value="">All Events</option>
                    <option value="cowrie.session.connect">Session Connect</option>
                    <option value="cowrie.login.success">Login Success</option>
                    <option value="cowrie.login.failed">Login Failed</option>
                    <option value="cowrie.command.input">Command Input</option>
                    <option value="cowrie.session.closed">Session Closed</option>
                </select>

                <label for="event-limit">Limit:</label>
                <select id="event-limit">
                    <option value="50">50</option>
                    <option value="100" selected>100</option>
                    <option value="500">500</option>
                    <option value="">All</option>
                </select>

                <button onclick="refreshEvents()">Refresh</button>

                <div class="export-buttons">
                    <a href="/api/export?format=json" class="export-btn" download>Export JSON</a>
                    <a href="/api/export?format=sql" class="export-btn sql" download>Export SQL</a>
                </div>
            </div>
        </div>

        <div class="events-container">
            <div class="events-header">
                <h3>Recent Events</h3>
                <div class="auto-refresh">
                    <input type="checkbox" id="auto-refresh" checked>
                    <label for="auto-refresh">Auto-refresh (5s)</label>
                </div>
            </div>
            <div class="events-list" id="events-list">
                <div class="loading">Loading events...</div>
            </div>
        </div>
    </div>

    <script>
        let lastEventTime = 0;
        let autoRefreshInterval;

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            refreshStats();
            refreshEvents();
            setupAutoRefresh();
        });

        function setupAutoRefresh() {
            const checkbox = document.getElementById('auto-refresh');

            function startAutoRefresh() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                }
                autoRefreshInterval = setInterval(() => {
                    refreshStats();
                    refreshEvents();
                }, 5000);
            }

            function stopAutoRefresh() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }

            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });

            if (checkbox.checked) {
                startAutoRefresh();
            }
        }

        async function refreshStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                if (data.success) {
                    const stats = data.stats;
                    document.getElementById('total-events').textContent = stats.total_events || 0;

                    // Calculate specific event type counts
                    const eventTypes = stats.event_types || {};
                    document.getElementById('active-sessions').textContent =
                        (eventTypes['cowrie.session.connect'] || 0) - (eventTypes['cowrie.session.closed'] || 0);
                    document.getElementById('login-attempts').textContent =
                        (eventTypes['cowrie.login.success'] || 0) + (eventTypes['cowrie.login.failed'] || 0);
                    document.getElementById('commands-executed').textContent =
                        eventTypes['cowrie.command.input'] || 0;
                }
            } catch (error) {
                console.error('Error refreshing stats:', error);
            }
        }

        async function refreshEvents() {
            try {
                const eventFilter = document.getElementById('event-filter').value;
                const eventLimit = document.getElementById('event-limit').value;

                let url = '/api/events?';
                if (eventFilter) url += `type=${encodeURIComponent(eventFilter)}&`;
                if (eventLimit) url += `limit=${eventLimit}&`;
                if (lastEventTime > 0) url += `since=${lastEventTime}&`;

                const response = await fetch(url);
                const data = await response.json();

                if (data.success) {
                    displayEvents(data.events);
                    if (data.events.length > 0) {
                        lastEventTime = Math.max(...data.events.map(e => e.received_at || 0));
                    }
                } else {
                    showError('Failed to load events: ' + data.error);
                }
            } catch (error) {
                console.error('Error refreshing events:', error);
                showError('Network error while loading events');
            }
        }

        function displayEvents(events) {
            const eventsList = document.getElementById('events-list');

            if (events.length === 0) {
                eventsList.innerHTML = '<div class="loading">No events found</div>';
                return;
            }

            const eventsHtml = events.map(event => {
                const eventTime = new Date(event.timestamp || event.received_at * 1000);
                const timeStr = eventTime.toLocaleString();

                return `
                    <div class="event-item">
                        <div class="event-header">
                            <span class="event-type">${event.eventid || 'unknown'}</span>
                            <span class="event-time">${timeStr}</span>
                        </div>
                        <div class="event-details">
                            ${event.session ? `<div class="event-session">Session: ${event.session}</div>` : ''}
                            ${event.src_ip ? `<div>Source IP: ${event.src_ip}</div>` : ''}
                            ${event.message ? `<div>Message: ${event.message}</div>` : ''}
                            ${event.input ? `<div>Input: <code>${event.input}</code></div>` : ''}
                            ${event.username ? `<div>Username: ${event.username}</div>` : ''}
                            ${event.password ? `<div>Password: ${event.password}</div>` : ''}
                        </div>
                    </div>
                `;
            }).join('');

            eventsList.innerHTML = eventsHtml;
        }

        function showError(message) {
            const eventsList = document.getElementById('events-list');
            eventsList.innerHTML = `<div class="error">${message}</div>`;
        }

        // Event filter change handler
        document.getElementById('event-filter').addEventListener('change', function() {
            lastEventTime = 0; // Reset to get all events with new filter
            refreshEvents();
        });

        document.getElementById('event-limit').addEventListener('change', function() {
            lastEventTime = 0; // Reset to get all events with new limit
            refreshEvents();
        });
    </script>
</body>
</html>
        """

        return html_content.encode('utf-8')


class Output(cowrie.core.output.Output):
    """
    Web Dashboard output plugin for Cowrie
    """

    def start(self):
        """Start the web dashboard server"""
        self.port = CowrieConfig.getint("output_webdashboard", "port", fallback=8080)
        self.host = CowrieConfig.get("output_webdashboard", "host", fallback="0.0.0.0")
        self.debug = CowrieConfig.getboolean("output_webdashboard", "debug", fallback=False)
        self.max_events = CowrieConfig.getint("output_webdashboard", "max_events", fallback=1000)

        # Initialize event store
        self.event_store = EventStore(max_events=self.max_events)

        # Create web resources
        root = Resource()
        root.putChild(b"", DashboardResource())
        root.putChild(b"api", APIResource(self.event_store))

        # Start web server
        site = server.Site(root)
        self.web_port = reactor.listenTCP(self.port, site, interface=self.host)

        if self.debug:
            log.msg(f"[WebDashboard] Started on http://{self.host}:{self.port}")

    def stop(self):
        """Stop the web dashboard server"""
        if hasattr(self, 'web_port'):
            self.web_port.stopListening()
        if self.debug:
            log.msg("[WebDashboard] Stopped")

    def write(self, event):
        """Process and store events"""
        try:
            # Add event to store
            self.event_store.add_event(event)

            if self.debug:
                log.msg(f"[WebDashboard] Stored event: {event.get('eventid', 'unknown')}")

        except Exception as e:
            if self.debug:
                log.msg(f"[WebDashboard] Error storing event: {e}")
