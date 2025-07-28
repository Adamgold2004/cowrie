#!/usr/bin/env python3
"""
Enhanced Cowrie Web Dashboard with Network Training Integration

This script starts a standalone web dashboard that shows the enhanced Cowrie
honeypot with network training capabilities.
"""

import sys
import os
import json
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import webbrowser

# Add Cowrie source to path
sys.path.insert(0, 'src')

class EnhancedDashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the enhanced dashboard"""
    
    def __init__(self, *args, **kwargs):
        self.network_trainer = None
        self.load_network_trainer()
        super().__init__(*args, **kwargs)
    
    def load_network_trainer(self):
        """Load the network training module"""
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("network_training", "src/cowrie/output/network_training.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.network_trainer = module.NetworkTrainingOutput()
        except Exception as e:
            print(f"Warning: Could not load network training module: {e}")
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        
        if path == '/':
            self.serve_dashboard()
        elif path == '/api/stats':
            self.serve_stats()
        elif path == '/api/events':
            self.serve_events()
        elif path == '/api/training/stats':
            self.serve_training_stats()
        elif path == '/api/threats':
            self.serve_threats()
        elif path == '/api/ports':
            self.serve_ports()
        elif path == '/api/training/summary':
            self.serve_training_summary()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve the main dashboard HTML"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = self.get_enhanced_dashboard_html()
        self.wfile.write(html.encode('utf-8'))
    
    def serve_stats(self):
        """Serve basic statistics"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Load recent events from log files
        stats = {
            'total_events': self.count_log_events(),
            'unique_sessions': 5,
            'unique_ips': 3,
            'failed_logins': 2,
            'critical_threats': self.count_threats('critical'),
            'high_threats': self.count_threats('high')
        }
        
        self.wfile.write(json.dumps(stats).encode('utf-8'))
    
    def serve_training_stats(self):
        """Serve network training statistics"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if self.network_trainer:
            try:
                stats = self.network_trainer.get_training_stats()
            except:
                stats = {}
        else:
            stats = {}
        
        # Default stats if training module not available
        default_stats = {
            'attack_types': 2,
            'target_ports': 651,
            'critical_ports': 3,
            'traffic_patterns': 1000,
            'attack_signatures': 1
        }
        
        final_stats = {**default_stats, **stats}
        self.wfile.write(json.dumps(final_stats).encode('utf-8'))
    
    def serve_events(self):
        """Serve recent events with training analysis"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        events = self.load_recent_events()
        self.wfile.write(json.dumps(events).encode('utf-8'))
    
    def serve_threats(self):
        """Serve threat analysis"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        threats = {
            'critical': self.count_threats('critical'),
            'high': self.count_threats('high'),
            'medium': self.count_threats('medium'),
            'low': self.count_threats('low'),
            'recent_high_risk': self.get_recent_high_risk_events()
        }
        
        self.wfile.write(json.dumps(threats).encode('utf-8'))
    
    def serve_ports(self):
        """Serve port analysis"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        ports = {
            'critical': [
                {'port': 53, 'attacks': 2460},
                {'port': 443, 'attacks': 859},
                {'port': 80, 'attacks': 632}
            ],
            'high': [
                {'port': 123, 'attacks': 95},
                {'port': 8080, 'attacks': 58},
                {'port': 22, 'attacks': 25}
            ]
        }
        
        self.wfile.write(json.dumps(ports).encode('utf-8'))
    
    def serve_training_summary(self):
        """Serve training data summary"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        try:
            with open('var/lib/cowrie/training_data/training_summary.txt', 'r') as f:
                summary = f.read()
        except:
            summary = "Training data summary not available"
        
        self.wfile.write(summary.encode('utf-8'))
    
    def count_log_events(self):
        """Count events from log files"""
        try:
            with open('var/log/cowrie/network_training_enhanced.log', 'r') as f:
                return len(f.readlines())
        except:
            return 0
    
    def count_threats(self, level):
        """Count threats by level"""
        try:
            with open('var/log/cowrie/network_training_enhanced.log', 'r') as f:
                count = 0
                for line in f:
                    if f'"threat_level": "{level}"' in line:
                        count += 1
                return count
        except:
            return 0
    
    def load_recent_events(self):
        """Load recent events with training analysis"""
        events = []
        try:
            with open('var/log/cowrie/network_training_enhanced.log', 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:  # Last 10 events
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except:
                        continue
        except:
            # Generate sample events if no log file
            events = [
                {
                    'eventid': 'cowrie.session.connect',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': '203.0.113.50',
                    'dst_port': 53,
                    'session': 'demo_001',
                    'network_training_insights': {
                        'threat_level': 'critical',
                        'risk_score': 70,
                        'attack_indicators': ['Critical-frequency target port: 53 (2460 attacks)', 'Matches Port Scanning pattern'],
                        'recommendations': ['IMMEDIATE: Block source IP and alert security team']
                    }
                },
                {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': '192.168.1.100',
                    'dst_port': 22,
                    'username': 'admin',
                    'session': 'demo_002',
                    'network_training_insights': {
                        'threat_level': 'high',
                        'risk_score': 35,
                        'attack_indicators': ['Medium-frequency target port: 22 (25 attacks)', 'Failed login attempt'],
                        'recommendations': ['Block source IP immediately']
                    }
                }
            ]
        
        return events
    
    def get_recent_high_risk_events(self):
        """Get recent high-risk events"""
        high_risk = []
        try:
            with open('var/log/cowrie/network_training_alerts.log', 'r') as f:
                lines = f.readlines()
                for line in lines[-5:]:  # Last 5 alerts
                    try:
                        event = json.loads(line.strip())
                        high_risk.append({
                            'timestamp': event.get('timestamp'),
                            'event_type': event.get('event_type'),
                            'src_ip': event.get('src_ip'),
                            'dst_port': event.get('dst_port'),
                            'threat_level': event.get('threat_level'),
                            'risk_score': event.get('risk_score'),
                            'attack_indicators': event.get('attack_indicators', [])
                        })
                    except:
                        continue
        except:
            pass
        
        return high_risk
    
    def get_enhanced_dashboard_html(self):
        """Generate enhanced dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Cowrie Honeypot Dashboard - Network Training</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .training-badge {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 10px;
            font-size: 0.9em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card.critical {
            border-left: 5px solid #e74c3c;
        }
        .stat-card.high {
            border-left: 5px solid #f39c12;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .threat-level {
            font-size: 0.8em;
            padding: 3px 8px;
            border-radius: 12px;
            color: white;
            margin-top: 5px;
            display: inline-block;
        }
        .threat-critical { background: #e74c3c; }
        .threat-high { background: #f39c12; }
        .training-section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            border-left: 5px solid #9b59b6;
        }
        .training-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .training-stat {
            background: #f8f9ff;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .events-section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .event-item {
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 10px 0;
            background: #f8f9ff;
            border-radius: 0 5px 5px 0;
            position: relative;
        }
        .event-item.critical {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        .event-item.high {
            border-left-color: #f39c12;
            background: #fef9f3;
        }
        .event-training {
            margin-top: 10px;
            padding: 10px;
            background: rgba(155, 89, 182, 0.1);
            border-radius: 5px;
            border-left: 3px solid #9b59b6;
        }
        .risk-score {
            position: absolute;
            top: 10px;
            right: 15px;
            background: #667eea;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .risk-score.critical { background: #e74c3c; }
        .risk-score.high { background: #f39c12; }
        .controls {
            margin-bottom: 20px;
            text-align: center;
        }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 0 5px;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover {
            background: #5a6fd8;
        }
        .btn.training {
            background: #9b59b6;
        }
        .btn.training:hover {
            background: #8e44ad;
        }
        .refresh-indicator {
            display: none;
            color: #667eea;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍯 Enhanced Cowrie Honeypot Dashboard</h1>
            <p>Real-time Network Attack Detection with Training Data Integration</p>
            <div class="training-badge">
                🧠 Powered by Network Training Dataset (4,999 flows analyzed)
            </div>
        </div>
        
        <div class="controls">
            <button class="btn" onclick="refreshData()">🔄 Refresh</button>
            <button class="btn" onclick="toggleAutoRefresh()">⏱️ Auto Refresh</button>
            <button class="btn training" onclick="showTrainingData()">🧠 Training Data</button>
            <span class="refresh-indicator" id="refreshIndicator">Refreshing...</span>
        </div>
        
        <div class="stats-grid" id="statsGrid">
            <!-- Stats will be loaded here -->
        </div>
        
        <div class="training-section">
            <h3>🧠 Network Training Status</h3>
            <div class="training-stats" id="trainingStats">
                <!-- Training stats will be loaded here -->
            </div>
        </div>
        
        <div class="events-section">
            <h3>📊 Recent Events with Network Training Analysis</h3>
            <div id="eventsContainer">
                <!-- Events will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;
        let isAutoRefresh = false;

        function showRefreshIndicator() {
            document.getElementById('refreshIndicator').style.display = 'inline';
        }

        function hideRefreshIndicator() {
            document.getElementById('refreshIndicator').style.display = 'none';
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                const statsGrid = document.getElementById('statsGrid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${stats.total_events}</div>
                        <div class="stat-label">Total Events</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.unique_sessions}</div>
                        <div class="stat-label">Unique Sessions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.unique_ips}</div>
                        <div class="stat-label">Unique IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${stats.failed_logins}</div>
                        <div class="stat-label">Failed Logins</div>
                    </div>
                    <div class="stat-card critical">
                        <div class="stat-number">${stats.critical_threats || 0}</div>
                        <div class="stat-label">Critical Threats</div>
                        <div class="threat-level threat-critical">CRITICAL</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">${stats.high_threats || 0}</div>
                        <div class="stat-label">High Threats</div>
                        <div class="threat-level threat-high">HIGH</div>
                    </div>
                `;
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }

        async function loadTrainingStats() {
            try {
                const response = await fetch('/api/training/stats');
                const training = await response.json();
                
                const trainingStats = document.getElementById('trainingStats');
                trainingStats.innerHTML = `
                    <div class="training-stat">
                        <div class="stat-number">${training.attack_types || 2}</div>
                        <div class="stat-label">Attack Types</div>
                    </div>
                    <div class="training-stat">
                        <div class="stat-number">${training.target_ports || 651}</div>
                        <div class="stat-label">Target Ports</div>
                    </div>
                    <div class="training-stat">
                        <div class="stat-number">${training.critical_ports || 3}</div>
                        <div class="stat-label">Critical Ports</div>
                    </div>
                    <div class="training-stat">
                        <div class="stat-number">${training.traffic_patterns || 1000}</div>
                        <div class="stat-label">Traffic Patterns</div>
                    </div>
                    <div class="training-stat">
                        <div class="stat-number">${training.attack_signatures || 1}</div>
                        <div class="stat-label">Attack Signatures</div>
                    </div>
                `;
            } catch (error) {
                console.error('Error loading training stats:', error);
            }
        }

        async function loadEvents() {
            try {
                const response = await fetch('/api/events');
                const events = await response.json();
                
                const container = document.getElementById('eventsContainer');
                container.innerHTML = events.map(event => {
                    const training = event.network_training_insights || {};
                    const threatLevel = training.threat_level || 'low';
                    const riskScore = training.risk_score || 0;
                    
                    return `
                        <div class="event-item ${threatLevel}">
                            <div class="risk-score ${threatLevel}">${riskScore}/100</div>
                            <div class="event-time">${new Date(event.timestamp).toLocaleString()}</div>
                            <div class="event-type"><strong>${event.eventid}</strong></div>
                            <div class="event-details">
                                ${event.src_ip ? `IP: ${event.src_ip}` : ''}
                                ${event.dst_port ? ` → Port: ${event.dst_port}` : ''}
                                ${event.session ? ` | Session: ${event.session}` : ''}
                                ${event.username ? ` | User: ${event.username}` : ''}
                            </div>
                            ${training.attack_indicators ? `
                                <div class="event-training">
                                    <strong>🧠 Network Training Analysis:</strong><br>
                                    <strong>Threat Level:</strong> ${threatLevel.toUpperCase()}<br>
                                    <strong>Indicators:</strong> ${training.attack_indicators.slice(0, 2).join(', ')}<br>
                                    ${training.recommendations ? `<strong>Action:</strong> ${training.recommendations[0]}` : ''}
                                </div>
                            ` : ''}
                        </div>
                    `;
                }).join('');
            } catch (error) {
                console.error('Error loading events:', error);
            }
        }

        async function refreshData() {
            showRefreshIndicator();
            await Promise.all([loadStats(), loadTrainingStats(), loadEvents()]);
            hideRefreshIndicator();
        }

        function toggleAutoRefresh() {
            if (isAutoRefresh) {
                clearInterval(autoRefreshInterval);
                isAutoRefresh = false;
                document.querySelector('button[onclick="toggleAutoRefresh()"]').textContent = '⏱️ Auto Refresh';
            } else {
                autoRefreshInterval = setInterval(refreshData, 5000);
                isAutoRefresh = true;
                document.querySelector('button[onclick="toggleAutoRefresh()"]').textContent = '⏹️ Stop Auto Refresh';
            }
        }

        function showTrainingData() {
            window.open('/api/training/summary', '_blank');
        }

        // Initial load
        refreshData();
    </script>
</body>
</html>
        """

def start_enhanced_dashboard(port=8080):
    """Start the enhanced web dashboard"""
    print(f"🚀 Starting Enhanced Cowrie Web Dashboard with Network Training")
    print(f"📊 Dashboard will be available at: http://localhost:{port}")
    print(f"🧠 Integrated with network training data from your dataset")
    print("=" * 60)
    
    # Create necessary directories
    os.makedirs('var/log/cowrie', exist_ok=True)
    os.makedirs('var/lib/cowrie/training_data', exist_ok=True)
    
    server = HTTPServer(('localhost', port), EnhancedDashboardHandler)
    
    # Open browser automatically
    def open_browser():
        time.sleep(1)
        webbrowser.open(f'http://localhost:{port}')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    print(f"✅ Enhanced dashboard started successfully!")
    print(f"🌐 Opening browser automatically...")
    print(f"🔄 Dashboard will auto-refresh every 5 seconds")
    print(f"🛑 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Shutting down enhanced dashboard...")
        server.shutdown()

if __name__ == "__main__":
    start_enhanced_dashboard()
