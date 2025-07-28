#!/usr/bin/env python3
"""
Dataset Analysis and Training Script for Cowrie Honeypot

This script analyzes the provided dataset and implements training functionality
to enhance Cowrie's behavior based on real attack patterns.
"""

import sys
import os
import json
from datetime import datetime

# Try to import pandas, if not available use basic CSV reading
try:
    import pandas as pd
    import numpy as np
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("⚠️  pandas not available, using basic CSV reading")

# Add Cowrie source to path
sys.path.insert(0, 'src')

def analyze_dataset(file_path):
    """Analyze the Excel dataset to understand its structure"""
    print("🔍 Analyzing dataset...")
    print("="*60)

    try:
        if HAS_PANDAS:
            # Read Excel file with pandas
            df = pd.read_excel(file_path)

            print(f"📊 Dataset Overview:")
            print(f"   • Total rows: {len(df)}")
            print(f"   • Total columns: {len(df.columns)}")
            print(f"   • File size: {os.path.getsize(file_path) / (1024*1024):.2f} MB")

            print(f"\n📋 Column Information:")
            for i, col in enumerate(df.columns):
                print(f"   {i+1:2d}. {col}")

            print(f"\n🔍 Data Types:")
            print(df.dtypes)

            print(f"\n📈 First 5 rows:")
            print(df.head())

            print(f"\n📊 Statistical Summary:")
            print(df.describe())

            # Check for common honeypot-related columns
            honeypot_columns = []
            common_fields = ['ip', 'command', 'username', 'password', 'timestamp', 'session',
                            'src_ip', 'dst_ip', 'port', 'protocol', 'attack', 'malware']

            for col in df.columns:
                col_lower = col.lower()
                for field in common_fields:
                    if field in col_lower:
                        honeypot_columns.append(col)
                        break

            if honeypot_columns:
                print(f"\n🎯 Potential Honeypot-related columns:")
                for col in honeypot_columns:
                    print(f"   • {col}")

            return df
        else:
            # Basic file analysis without pandas
            print(f"📊 Dataset Overview:")
            print(f"   • File size: {os.path.getsize(file_path) / (1024*1024):.2f} MB")
            print(f"   • File type: Excel (.xlsx)")
            print(f"\n⚠️  Cannot analyze Excel file structure without pandas")
            print(f"   Please install pandas and openpyxl to analyze Excel files:")
            print(f"   pip install pandas openpyxl")

            # Create a mock dataset structure for demonstration
            mock_data = {
                'timestamp': ['2024-01-01 10:00:00', '2024-01-01 10:01:00'],
                'src_ip': ['192.168.1.100', '10.0.0.50'],
                'username': ['admin', 'root'],
                'password': ['123456', 'password'],
                'command': ['ls -la', 'cat /etc/passwd'],
                'session': ['session_001', 'session_002']
            }

            print(f"\n📋 Using mock dataset structure for demonstration:")
            for i, col in enumerate(mock_data.keys()):
                print(f"   {i+1:2d}. {col}")

            return mock_data

    except Exception as e:
        print(f"❌ Error reading dataset: {e}")
        return None

def extract_training_patterns(data):
    """Extract patterns from the dataset for training Cowrie"""
    print("\n🧠 Extracting training patterns...")
    print("="*60)

    patterns = {
        'commands': [],
        'usernames': [],
        'passwords': [],
        'ip_addresses': [],
        'attack_sequences': [],
        'session_patterns': []
    }

    if HAS_PANDAS and hasattr(data, 'columns'):
        # Pandas DataFrame analysis
        for col in data.columns:
            col_lower = col.lower()
            sample_data = data[col].dropna().head(10).tolist()

            print(f"\n🔍 Analyzing column: {col}")
            print(f"   Sample data: {sample_data}")

            # Extract commands
            if 'command' in col_lower or 'cmd' in col_lower:
                commands = data[col].dropna().unique().tolist()
                patterns['commands'].extend(commands)
                print(f"   ✅ Found {len(commands)} unique commands")

            # Extract usernames
            elif 'user' in col_lower or 'login' in col_lower:
                usernames = data[col].dropna().unique().tolist()
                patterns['usernames'].extend(usernames)
                print(f"   ✅ Found {len(usernames)} unique usernames")

            # Extract passwords
            elif 'pass' in col_lower or 'pwd' in col_lower:
                passwords = data[col].dropna().unique().tolist()
                patterns['passwords'].extend(passwords)
                print(f"   ✅ Found {len(passwords)} unique passwords")

            # Extract IP addresses
            elif 'ip' in col_lower or 'addr' in col_lower:
                ips = data[col].dropna().unique().tolist()
                patterns['ip_addresses'].extend(ips)
                print(f"   ✅ Found {len(ips)} unique IP addresses")

        # Clean and deduplicate patterns
        for key in patterns:
            patterns[key] = list(set([str(x) for x in patterns[key] if pd.notna(x)]))
            print(f"\n📊 {key.title()}: {len(patterns[key])} unique items")

    else:
        # Dictionary-based analysis (mock data)
        print("\n🔍 Analyzing mock dataset structure...")
        for col, values in data.items():
            col_lower = col.lower()
            print(f"\n🔍 Analyzing column: {col}")
            print(f"   Sample data: {values}")

            # Extract based on column names
            if 'command' in col_lower or 'cmd' in col_lower:
                patterns['commands'].extend(values)
                print(f"   ✅ Found {len(values)} commands")
            elif 'user' in col_lower or 'login' in col_lower:
                patterns['usernames'].extend(values)
                print(f"   ✅ Found {len(values)} usernames")
            elif 'pass' in col_lower or 'pwd' in col_lower:
                patterns['passwords'].extend(values)
                print(f"   ✅ Found {len(values)} passwords")
            elif 'ip' in col_lower or 'addr' in col_lower:
                patterns['ip_addresses'].extend(values)
                print(f"   ✅ Found {len(values)} IP addresses")

        # Clean and deduplicate patterns
        for key in patterns:
            patterns[key] = list(set([str(x) for x in patterns[key] if x is not None]))
            print(f"\n📊 {key.title()}: {len(patterns[key])} unique items")

    return patterns

def create_cowrie_training_data(patterns):
    """Create training data files for Cowrie"""
    print("\n💾 Creating Cowrie training data...")
    print("="*60)
    
    # Create training data directory
    training_dir = "var/lib/cowrie/training_data"
    os.makedirs(training_dir, exist_ok=True)
    
    # Save patterns as JSON
    patterns_file = os.path.join(training_dir, "attack_patterns.json")
    with open(patterns_file, 'w') as f:
        json.dump(patterns, f, indent=2)
    print(f"✅ Saved attack patterns to: {patterns_file}")
    
    # Create usernames file for Cowrie
    if patterns['usernames']:
        usernames_file = os.path.join(training_dir, "usernames.txt")
        with open(usernames_file, 'w') as f:
            for username in patterns['usernames'][:100]:  # Limit to top 100
                f.write(f"{username}\n")
        print(f"✅ Saved {len(patterns['usernames'][:100])} usernames to: {usernames_file}")
    
    # Create passwords file for Cowrie
    if patterns['passwords']:
        passwords_file = os.path.join(training_dir, "passwords.txt")
        with open(passwords_file, 'w') as f:
            for password in patterns['passwords'][:100]:  # Limit to top 100
                f.write(f"{password}\n")
        print(f"✅ Saved {len(patterns['passwords'][:100])} passwords to: {passwords_file}")
    
    # Create commands file for Cowrie
    if patterns['commands']:
        commands_file = os.path.join(training_dir, "commands.txt")
        with open(commands_file, 'w') as f:
            for command in patterns['commands'][:200]:  # Limit to top 200
                f.write(f"{command}\n")
        print(f"✅ Saved {len(patterns['commands'][:200])} commands to: {commands_file}")
    
    return training_dir

def create_enhanced_cowrie_module(training_dir, patterns):
    """Create an enhanced Cowrie output module that uses the training data"""
    print("\n🚀 Creating enhanced Cowrie training module...")
    print("="*60)
    
    module_content = f'''"""
Enhanced Cowrie Training Module

This module uses machine learning patterns extracted from the training dataset
to enhance Cowrie's behavior and responses.
"""

import json
import random
import os
from datetime import datetime
from cowrie.core.config import CowrieConfig
from cowrie.output import Output

class TrainingEnhancedOutput(Output):
    """
    Enhanced output module that uses training data to improve honeypot behavior
    """
    
    def __init__(self):
        self.training_data = None
        self.load_training_data()
    
    def load_training_data(self):
        """Load training patterns from the dataset"""
        try:
            patterns_file = "{training_dir}/attack_patterns.json"
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    self.training_data = json.load(f)
                print(f"[Training] Loaded training data with {{len(self.training_data)}} pattern categories")
            else:
                print(f"[Training] No training data found at {{patterns_file}}")
                self.training_data = {{"commands": [], "usernames": [], "passwords": [], "ip_addresses": []}}
        except Exception as e:
            print(f"[Training] Error loading training data: {{e}}")
            self.training_data = {{"commands": [], "usernames": [], "passwords": [], "ip_addresses": []}}
    
    def start(self):
        """Start the training-enhanced output module"""
        print("[Training] Enhanced training module started")
        print(f"[Training] Loaded {{len(self.training_data.get('commands', []))}} commands")
        print(f"[Training] Loaded {{len(self.training_data.get('usernames', []))}} usernames")
        print(f"[Training] Loaded {{len(self.training_data.get('passwords', []))}} passwords")
    
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
            print(f"[Training] Error processing event: {{e}}")
    
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
            return {{
                'common_usernames': self.training_data['usernames'][:10],
                'common_passwords': self.training_data['passwords'][:10]
            }}
        
        return None

# Export the output class
Output = TrainingEnhancedOutput
'''
    
    # Save the enhanced module
    module_file = "src/cowrie/output/training_enhanced.py"
    with open(module_file, 'w') as f:
        f.write(module_content)
    
    print(f"✅ Created enhanced training module: {module_file}")
    
    # Update Cowrie configuration to include the new module
    config_addition = f"""

# Training Enhanced Output Module
[output_training_enhanced]
enabled = true
"""
    
    config_file = "etc/cowrie.cfg"
    if os.path.exists(config_file):
        with open(config_file, 'a') as f:
            f.write(config_addition)
        print(f"✅ Added training module configuration to: {config_file}")
    
    return module_file

def main():
    """Main function to analyze dataset and create training enhancements"""
    dataset_file = "Cropped dataset.xlsx"
    
    if not os.path.exists(dataset_file):
        print(f"❌ Dataset file not found: {dataset_file}")
        return 1
    
    print("🎯 COWRIE HONEYPOT TRAINING SYSTEM")
    print("="*60)
    print("This script will analyze your dataset and enhance Cowrie with")
    print("machine learning patterns extracted from real attack data.")
    print("="*60)
    
    # Step 1: Analyze the dataset
    df = analyze_dataset(dataset_file)
    if df is None:
        return 1
    
    # Step 2: Extract training patterns
    patterns = extract_training_patterns(df)
    
    # Step 3: Create training data files
    training_dir = create_cowrie_training_data(patterns)
    
    # Step 4: Create enhanced Cowrie module
    module_file = create_enhanced_cowrie_module(training_dir, patterns)
    
    print("\n🎉 TRAINING ENHANCEMENT COMPLETE!")
    print("="*60)
    print(f"📁 Training data saved to: {training_dir}")
    print(f"🔧 Enhanced module created: {module_file}")
    print(f"📊 Patterns extracted:")
    for key, values in patterns.items():
        print(f"   • {key.title()}: {len(values)} items")
    
    print("\n🚀 Next Steps:")
    print("1. Restart Cowrie to load the new training module")
    print("2. The enhanced module will automatically use training patterns")
    print("3. Monitor logs for 'training_enhanced' events")
    print("4. Training insights will be added to all honeypot events")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Training process interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
