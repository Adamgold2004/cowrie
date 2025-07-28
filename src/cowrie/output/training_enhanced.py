"""
Enhanced Cowrie Training Module

This module uses machine learning patterns extracted from the network attack dataset
to enhance Cowrie's behavior, detection capabilities, and threat intelligence.
"""

import json
import random
import os
from datetime import datetime
from cowrie.core.config import CowrieConfig
from cowrie.output import Output

class TrainingEnhancedOutput(Output):
    """
    Enhanced output module that uses real network attack data to improve honeypot behavior
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
                print(f"[Training] Loaded network patterns with {len(self.network_patterns.get('attack_types', []))} attack types")

            # Load attack signatures
            signatures_file = "var/lib/cowrie/training_data/attack_signatures.json"
            if os.path.exists(signatures_file):
                with open(signatures_file, 'r') as f:
                    self.attack_signatures = json.load(f)
                print(f"[Training] Loaded {len(self.attack_signatures)} attack signatures")

            # Load target ports
            ports_file = "var/lib/cowrie/training_data/target_ports.txt"
            if os.path.exists(ports_file):
                self.target_ports = {}
                with open(ports_file, 'r') as f:
                    for line in f:
                        if '\t' in line:
                            port, count = line.strip().split('\t')
                            self.target_ports[port] = int(count)
                print(f"[Training] Loaded {len(self.target_ports)} target ports")

            # Load traffic patterns
            traffic_file = "var/lib/cowrie/training_data/traffic_patterns.json"
            if os.path.exists(traffic_file):
                with open(traffic_file, 'r') as f:
                    self.traffic_patterns = json.load(f)
                print(f"[Training] Loaded {len(self.traffic_patterns)} traffic patterns")

            if not any([self.network_patterns, self.attack_signatures, self.target_ports]):
                print(f"[Training] No training data found, using defaults")
                self.network_patterns = {"attack_types": [], "port_patterns": []}
                self.attack_signatures = []
                self.target_ports = {}

        except Exception as e:
            print(f"[Training] Error loading training data: {e}")
            self.network_patterns = {"attack_types": [], "port_patterns": []}
            self.attack_signatures = []
            self.target_ports = {}
    
    def start(self):
        """Start the training-enhanced output module"""
        print("[Training] Enhanced training module started")
        print(f"[Training] Loaded {len(self.training_data.get('commands', []))} commands")
        print(f"[Training] Loaded {len(self.training_data.get('usernames', []))} usernames")
        print(f"[Training] Loaded {len(self.training_data.get('passwords', []))} passwords")
    
    def stop(self):
        """Stop the training-enhanced output module"""
        print("[Training] Enhanced training module stopped")
    
    def write(self, event):
        """Process events and enhance them with training data insights"""
        try:
            eventid = event.get('eventid', '')
            
            # Enhance login attempts with training data
            if 'login' in eventid:
                self.enhance_login_event(event)
            
            # Enhance command events with training data
            elif 'command' in eventid:
                self.enhance_command_event(event)
            
            # Enhance session events with training data
            elif 'session' in eventid:
                self.enhance_session_event(event)
            
            # Add training insights to all events
            event['training_enhanced'] = True
            event['training_timestamp'] = datetime.now().isoformat()
            
        except Exception as e:
            print(f"[Training] Error processing event: {e}")
    
    def enhance_login_event(self, event):
        """Enhance login events with training data insights"""
        username = event.get('username', '')
        password = event.get('password', '')
        
        # Check if credentials match training patterns
        if username in self.training_data.get('usernames', []):
            event['training_username_seen'] = True
            event['training_username_frequency'] = self.training_data['usernames'].count(username)
        
        if password in self.training_data.get('passwords', []):
            event['training_password_seen'] = True
            event['training_password_frequency'] = self.training_data['passwords'].count(password)
        
        # Predict attack sophistication based on training data
        if username in self.training_data.get('usernames', []) and password in self.training_data.get('passwords', []):
            event['training_attack_sophistication'] = 'high'
        elif username in self.training_data.get('usernames', []) or password in self.training_data.get('passwords', []):
            event['training_attack_sophistication'] = 'medium'
        else:
            event['training_attack_sophistication'] = 'low'
    
    def enhance_command_event(self, event):
        """Enhance command events with training data insights"""
        command = event.get('input', '')
        
        if command in self.training_data.get('commands', []):
            event['training_command_seen'] = True
            event['training_command_frequency'] = self.training_data['commands'].count(command)
            
            # Categorize command based on training patterns
            if any(malware_cmd in command.lower() for malware_cmd in ['wget', 'curl', 'nc', 'ncat']):
                event['training_command_category'] = 'malware_download'
            elif any(recon_cmd in command.lower() for recon_cmd in ['ps', 'netstat', 'ifconfig', 'whoami']):
                event['training_command_category'] = 'reconnaissance'
            elif any(persist_cmd in command.lower() for persist_cmd in ['crontab', 'systemctl', 'service']):
                event['training_command_category'] = 'persistence'
            else:
                event['training_command_category'] = 'general'
    
    def enhance_session_event(self, event):
        """Enhance session events with training data insights"""
        src_ip = event.get('src_ip', '')
        
        if src_ip in self.training_data.get('ip_addresses', []):
            event['training_ip_seen'] = True
            event['training_ip_frequency'] = self.training_data['ip_addresses'].count(src_ip)
    
    def get_suggested_response(self, event_type, context):
        """Get suggested responses based on training data"""
        if event_type == 'command' and self.training_data.get('commands'):
            # Suggest related commands that attackers might try next
            return random.sample(self.training_data['commands'], min(3, len(self.training_data['commands'])))
        
        elif event_type == 'login' and self.training_data.get('usernames'):
            # Suggest common username/password combinations
            return {
                'common_usernames': self.training_data['usernames'][:10],
                'common_passwords': self.training_data['passwords'][:10]
            }
        
        return None

# Export the output class
Output = TrainingEnhancedOutput
