"""
Network Attack Training Module for Cowrie

This module uses real network attack patterns extracted from the dataset
to enhance Cowrie's threat detection and response capabilities.
"""

import json
import random
import os
from datetime import datetime
try:
    from cowrie.core.config import CowrieConfig
    from cowrie.output import Output
    COWRIE_AVAILABLE = True
except ImportError:
    # For testing without full Cowrie installation
    COWRIE_AVAILABLE = False
    class Output:
        pass

class NetworkTrainingOutput(Output):
    """
    Network training output module that uses real attack data to improve honeypot behavior
    """
    
    def __init__(self):
        self.network_patterns = None
        self.attack_signatures = None
        self.target_ports = None
        self.traffic_patterns = None
        self.load_training_data()
    
    def load_training_data(self):
        """Load training patterns from the network attack dataset"""
        try:
            # Load network attack patterns
            patterns_file = "var/lib/cowrie/training_data/network_attack_patterns.json"
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    self.network_patterns = json.load(f)
                print(f"[NetworkTraining] Loaded network patterns with {len(self.network_patterns.get('attack_types', []))} attack types")
            
            # Load attack signatures
            signatures_file = "var/lib/cowrie/training_data/attack_signatures.json"
            if os.path.exists(signatures_file):
                with open(signatures_file, 'r') as f:
                    self.attack_signatures = json.load(f)
                print(f"[NetworkTraining] Loaded {len(self.attack_signatures)} attack signatures")
            
            # Load target ports
            ports_file = "var/lib/cowrie/training_data/target_ports.txt"
            if os.path.exists(ports_file):
                self.target_ports = {}
                with open(ports_file, 'r') as f:
                    for line in f:
                        if '\t' in line:
                            port, count = line.strip().split('\t')
                            self.target_ports[port] = int(count)
                print(f"[NetworkTraining] Loaded {len(self.target_ports)} target ports")
            
            # Load traffic patterns
            traffic_file = "var/lib/cowrie/training_data/traffic_patterns.json"
            if os.path.exists(traffic_file):
                with open(traffic_file, 'r') as f:
                    self.traffic_patterns = json.load(f)
                print(f"[NetworkTraining] Loaded {len(self.traffic_patterns)} traffic patterns")
            
            if not any([self.network_patterns, self.attack_signatures, self.target_ports]):
                print(f"[NetworkTraining] No training data found, using defaults")
                self.network_patterns = {"attack_types": [], "port_patterns": []}
                self.attack_signatures = []
                self.target_ports = {}
                
        except Exception as e:
            print(f"[NetworkTraining] Error loading training data: {e}")
            self.network_patterns = {"attack_types": [], "port_patterns": []}
            self.attack_signatures = []
            self.target_ports = {}
    
    def start(self):
        """Start the network training output module"""
        print("[NetworkTraining] Network attack training module started")
        if self.network_patterns:
            print(f"[NetworkTraining] Loaded {len(self.network_patterns.get('attack_types', []))} attack types")
            print(f"[NetworkTraining] Loaded {len(self.network_patterns.get('port_patterns', []))} target ports")
        if self.attack_signatures:
            print(f"[NetworkTraining] Loaded {len(self.attack_signatures)} attack signatures")
        if self.target_ports:
            print(f"[NetworkTraining] Loaded {len(self.target_ports)} port frequency patterns")
            high_risk_ports = [p for p, f in self.target_ports.items() if f > 100]
            print(f"[NetworkTraining] Identified {len(high_risk_ports)} high-risk ports")
    
    def stop(self):
        """Stop the network training output module"""
        print("[NetworkTraining] Network attack training module stopped")
    
    def write(self, event):
        """Process events and add network attack training insights"""
        try:
            # Add network training insights to the event
            enhanced_event = dict(event)
            enhanced_event['network_training_insights'] = self.analyze_network_event(event)
            
            # Log the enhanced event
            self.log_enhanced_event(enhanced_event)
            
        except Exception as e:
            print(f"[NetworkTraining] Error processing event: {e}")
    
    def analyze_network_event(self, event):
        """Analyze event using network attack training data patterns"""
        insights = {
            'threat_level': 'low',
            'attack_indicators': [],
            'port_analysis': {},
            'recommendations': [],
            'training_source': 'network_dataset',
            'risk_score': 0
        }
        
        try:
            # Analyze destination port patterns
            dst_port = event.get('dst_port') or event.get('port')
            if dst_port and self.target_ports:
                port_str = str(dst_port)
                if port_str in self.target_ports:
                    frequency = self.target_ports[port_str]
                    risk_level = self.assess_port_risk(frequency)
                    
                    insights['port_analysis'] = {
                        'port': dst_port,
                        'frequency_in_attacks': frequency,
                        'risk_level': risk_level
                    }
                    
                    # Adjust threat level and risk score based on port frequency
                    if frequency > 500:
                        insights['attack_indicators'].append(f"Critical-frequency target port: {dst_port} ({frequency} attacks)")
                        insights['threat_level'] = 'critical'
                        insights['risk_score'] += 50
                    elif frequency > 100:
                        insights['attack_indicators'].append(f"High-frequency target port: {dst_port} ({frequency} attacks)")
                        insights['threat_level'] = 'high'
                        insights['risk_score'] += 30
                    elif frequency > 20:
                        insights['attack_indicators'].append(f"Medium-frequency target port: {dst_port} ({frequency} attacks)")
                        if insights['threat_level'] == 'low':
                            insights['threat_level'] = 'medium'
                        insights['risk_score'] += 15
            
            # Check against known attack signatures
            if self.attack_signatures:
                for signature in self.attack_signatures:
                    if self.matches_attack_signature(event, signature):
                        insights['attack_indicators'].append(f"Matches {signature['name']} pattern")
                        if signature['severity'] == 'high':
                            insights['threat_level'] = 'high'
                            insights['risk_score'] += 25
                        elif signature['severity'] == 'medium' and insights['threat_level'] == 'low':
                            insights['threat_level'] = 'medium'
                            insights['risk_score'] += 15
            
            # Analyze session patterns for scanning behavior
            session_id = event.get('session')
            if session_id:
                scan_indicators = self.detect_scanning_behavior(event)
                if scan_indicators:
                    insights['attack_indicators'].extend(scan_indicators)
                    if insights['threat_level'] not in ['critical', 'high']:
                        insights['threat_level'] = 'high'
                    insights['risk_score'] += 20
            
            # Add recommendations based on threat level and indicators
            if insights['threat_level'] == 'critical':
                insights['recommendations'].extend([
                    "IMMEDIATE: Block source IP and alert security team",
                    "Increase monitoring on all target ports",
                    "Activate incident response procedures",
                    "Log all connection attempts for forensic analysis"
                ])
            elif insights['threat_level'] == 'high':
                insights['recommendations'].extend([
                    "Block source IP immediately",
                    "Increase monitoring on target ports",
                    "Alert security team",
                    "Log detailed connection attempts"
                ])
            elif insights['threat_level'] == 'medium':
                insights['recommendations'].extend([
                    "Monitor source IP closely",
                    "Rate limit connections",
                    "Log connection patterns"
                ])
            
        except Exception as e:
            insights['error'] = str(e)
        
        return insights
    
    def assess_port_risk(self, frequency):
        """Assess risk level based on port attack frequency"""
        if frequency > 1000:
            return 'critical'
        elif frequency > 500:
            return 'very_high'
        elif frequency > 100:
            return 'high'
        elif frequency > 20:
            return 'medium'
        else:
            return 'low'
    
    def matches_attack_signature(self, event, signature):
        """Check if event matches a known attack signature"""
        if signature['name'] == 'Port Scanning':
            return self.is_port_scanning_behavior(event)
        
        return False
    
    def is_port_scanning_behavior(self, event):
        """Detect port scanning behavior patterns"""
        eventid = event.get('eventid', '')
        
        # Look for connection events that might indicate scanning
        scanning_indicators = [
            'cowrie.session.connect',
            'cowrie.client.version',
            'cowrie.login.failed',
            'cowrie.session.closed'
        ]
        
        return eventid in scanning_indicators
    
    def detect_scanning_behavior(self, event):
        """Detect various scanning behavior patterns"""
        indicators = []
        
        # Check for rapid connections
        if event.get('eventid') == 'cowrie.session.connect':
            indicators.append("New connection attempt - potential scanning")
        
        # Check for failed login attempts (brute force indicator)
        if event.get('eventid') == 'cowrie.login.failed':
            indicators.append("Failed login attempt - possible brute force attack")
        
        # Check for version probing
        if event.get('eventid') == 'cowrie.client.version':
            indicators.append("Client version probing - reconnaissance activity")
        
        # Check for quick disconnections (scanning pattern)
        if event.get('eventid') == 'cowrie.session.closed':
            duration = event.get('duration', 0)
            if duration < 5:  # Very short sessions
                indicators.append("Quick disconnect - scanning behavior")
        
        return indicators
    
    def log_enhanced_event(self, event):
        """Log the enhanced event with network training insights"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            insights = event.get('network_training_insights', {})
            
            log_entry = {
                'timestamp': timestamp,
                'event_type': event.get('eventid', 'unknown'),
                'src_ip': event.get('src_ip', 'unknown'),
                'dst_port': event.get('dst_port') or event.get('port', 'unknown'),
                'session': event.get('session', 'unknown'),
                'threat_level': insights.get('threat_level', 'low'),
                'risk_score': insights.get('risk_score', 0),
                'attack_indicators': insights.get('attack_indicators', []),
                'recommendations': insights.get('recommendations', []),
                'network_training_insights': insights,
                'original_event': event
            }
            
            # Log to file
            log_file = "var/log/cowrie/network_training_enhanced.log"
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
            # Also log high-risk events to a separate file
            if insights.get('threat_level') in ['high', 'critical']:
                alert_file = "var/log/cowrie/network_training_alerts.log"
                with open(alert_file, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            print(f"[NetworkTraining] Error logging enhanced event: {e}")
    
    def get_training_stats(self):
        """Get statistics about the network training data"""
        stats = {}
        
        if self.network_patterns:
            stats.update({
                'attack_types': len(self.network_patterns.get('attack_types', [])),
                'port_patterns': len(self.network_patterns.get('port_patterns', [])),
                'traffic_patterns': len(self.network_patterns.get('traffic_patterns', []))
            })
        
        if self.attack_signatures:
            stats['attack_signatures'] = len(self.attack_signatures)
        
        if self.target_ports:
            stats['target_ports'] = len(self.target_ports)
            stats['high_risk_ports'] = len([p for p, f in self.target_ports.items() if f > 100])
            stats['critical_risk_ports'] = len([p for p, f in self.target_ports.items() if f > 500])
        
        return stats

# Export the output class
Output = NetworkTrainingOutput
