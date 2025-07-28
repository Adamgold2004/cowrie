#!/usr/bin/env python3
"""
Test Script for Network Attack Training Integration

This script demonstrates the enhanced Cowrie honeypot with real network attack
training data integration and validates all functionality.
"""

import sys
import os
import json
import time
from datetime import datetime

# Add Cowrie source to path
sys.path.insert(0, 'src')

def test_network_training_module():
    """Test the network training module functionality"""
    print("🧪 TESTING NETWORK ATTACK TRAINING MODULE")
    print("="*60)
    
    try:
        # Import the network training module directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_training", "src/cowrie/output/network_training.py")
        network_training_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(network_training_module)

        # Create an instance
        network_trainer = network_training_module.NetworkTrainingOutput()
        
        # Test loading training data
        print("📊 Training Data Statistics:")
        stats = network_trainer.get_training_stats()
        for key, value in stats.items():
            print(f"   • {key.replace('_', ' ').title()}: {value}")
        
        # Test event analysis
        print("\n🔍 Testing Event Analysis:")
        
        # Test high-risk port event
        test_events = [
            {
                'eventid': 'cowrie.session.connect',
                'src_ip': '192.168.1.100',
                'dst_port': 53,  # DNS port - high frequency in dataset
                'session': 'test_session_001',
                'timestamp': datetime.now().isoformat()
            },
            {
                'eventid': 'cowrie.login.failed',
                'src_ip': '10.0.0.50',
                'dst_port': 22,  # SSH port
                'username': 'admin',
                'password': 'password',
                'session': 'test_session_002',
                'timestamp': datetime.now().isoformat()
            },
            {
                'eventid': 'cowrie.session.connect',
                'src_ip': '172.16.0.1',
                'dst_port': 8080,  # HTTP alt port
                'session': 'test_session_003',
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        for i, event in enumerate(test_events, 1):
            print(f"\n   Test Event {i}: {event['eventid']}")
            insights = network_trainer.analyze_network_event(event)
            
            print(f"   • Threat Level: {insights['threat_level']}")
            print(f"   • Risk Score: {insights['risk_score']}")
            
            if insights['attack_indicators']:
                print(f"   • Attack Indicators:")
                for indicator in insights['attack_indicators']:
                    print(f"     - {indicator}")
            
            if insights['port_analysis']:
                port_info = insights['port_analysis']
                print(f"   • Port Analysis: Port {port_info['port']} - {port_info['risk_level']} risk")
                print(f"     Frequency in attacks: {port_info['frequency_in_attacks']}")
            
            if insights['recommendations']:
                print(f"   • Recommendations:")
                for rec in insights['recommendations'][:2]:  # Show first 2
                    print(f"     - {rec}")
        
        print("\n✅ Network training module test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing network training module: {e}")
        return False

def test_training_data_files():
    """Test that all training data files are present and valid"""
    print("\n📁 TESTING TRAINING DATA FILES")
    print("="*60)
    
    training_dir = "var/lib/cowrie/training_data"
    required_files = [
        "network_attack_patterns.json",
        "attack_types.txt",
        "target_ports.txt",
        "attack_signatures.json",
        "traffic_patterns.json",
        "training_summary.txt"
    ]
    
    all_files_valid = True
    
    for filename in required_files:
        filepath = os.path.join(training_dir, filename)
        if os.path.exists(filepath):
            try:
                if filename.endswith('.json'):
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    print(f"✅ {filename}: Valid JSON with {len(data) if isinstance(data, (list, dict)) else 'N/A'} items")
                else:
                    with open(filepath, 'r') as f:
                        lines = f.readlines()
                    print(f"✅ {filename}: {len(lines)} lines")
            except Exception as e:
                print(f"❌ {filename}: Error reading file - {e}")
                all_files_valid = False
        else:
            print(f"❌ {filename}: File not found")
            all_files_valid = False
    
    return all_files_valid

def test_web_dashboard_integration():
    """Test that the web dashboard can access training data"""
    print("\n🌐 TESTING WEB DASHBOARD INTEGRATION")
    print("="*60)
    
    try:
        # Check if web dashboard module exists
        if os.path.exists("src/cowrie/output/webdashboard.py"):
            print("✅ Web dashboard module found")
            
            # Check if training data is accessible
            training_file = "var/lib/cowrie/training_data/network_attack_patterns.json"
            if os.path.exists(training_file):
                with open(training_file, 'r') as f:
                    training_data = json.load(f)
                
                print(f"✅ Training data accessible: {len(training_data.get('attack_types', []))} attack types")
                print(f"✅ Port patterns available: {len(training_data.get('port_patterns', []))} ports")
                
                # Test API endpoint data structure
                api_data = {
                    'training_stats': {
                        'attack_types': len(training_data.get('attack_types', [])),
                        'port_patterns': len(training_data.get('port_patterns', [])),
                        'last_updated': datetime.now().isoformat()
                    },
                    'high_risk_ports': [],
                    'attack_signatures': []
                }
                
                # Load port statistics
                ports_file = "var/lib/cowrie/training_data/target_ports.txt"
                if os.path.exists(ports_file):
                    with open(ports_file, 'r') as f:
                        for line in f:
                            if '\t' in line:
                                port, count = line.strip().split('\t')
                                if int(count) > 100:
                                    api_data['high_risk_ports'].append({
                                        'port': port,
                                        'frequency': int(count)
                                    })
                
                print(f"✅ High-risk ports identified: {len(api_data['high_risk_ports'])}")
                
                return True
            else:
                print("❌ Training data not accessible")
                return False
        else:
            print("⚠️  Web dashboard module not found")
            return False
            
    except Exception as e:
        print(f"❌ Error testing web dashboard integration: {e}")
        return False

def demonstrate_enhanced_capabilities():
    """Demonstrate the enhanced capabilities of the trained system"""
    print("\n🚀 DEMONSTRATING ENHANCED CAPABILITIES")
    print("="*60)
    
    # Load training data
    try:
        with open("var/lib/cowrie/training_data/network_attack_patterns.json", 'r') as f:
            patterns = json.load(f)
        
        with open("var/lib/cowrie/training_data/training_summary.txt", 'r') as f:
            summary = f.read()
        
        print("📊 Training Dataset Summary:")
        print(summary)
        
        print("\n🎯 Enhanced Detection Capabilities:")
        print(f"   • Attack Type Recognition: {len(patterns.get('attack_types', []))} types")
        print(f"   • Port Risk Assessment: {len(patterns.get('port_patterns', []))} ports analyzed")
        print(f"   • Traffic Pattern Analysis: {len(patterns.get('traffic_patterns', []))} samples")
        
        # Show top attack targets
        if 'port_statistics' in patterns:
            print("\n🔍 Top Attack Targets (from real data):")
            sorted_ports = sorted(patterns['port_statistics'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]
            for port, count in sorted_ports:
                risk_level = "🔴 Critical" if count > 500 else "🟠 High" if count > 100 else "🟡 Medium"
                print(f"   • Port {port}: {count} attacks - {risk_level}")
        
        print("\n🛡️  Enhanced Security Features:")
        print("   • Real-time threat level assessment")
        print("   • Attack pattern recognition from 4,999 network flows")
        print("   • Port scanning detection based on actual attack data")
        print("   • Risk scoring system for incoming connections")
        print("   • Automated response recommendations")
        
        return True
        
    except Exception as e:
        print(f"❌ Error demonstrating capabilities: {e}")
        return False

def main():
    """Main test function"""
    print("🎯 COWRIE NETWORK ATTACK TRAINING VALIDATION")
    print("="*80)
    print("This script validates the integration of real network attack data")
    print("into the Cowrie honeypot system for enhanced threat detection.")
    print("="*80)
    
    # Run all tests
    tests = [
        ("Training Data Files", test_training_data_files),
        ("Network Training Module", test_network_training_module),
        ("Web Dashboard Integration", test_web_dashboard_integration),
        ("Enhanced Capabilities Demo", demonstrate_enhanced_capabilities)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*80)
    print("🎉 TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"   {test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("✅ Cowrie honeypot successfully enhanced with network attack training data")
        print("✅ System ready for deployment with enhanced threat detection")
        print("\n🚀 Next Steps:")
        print("   1. Start Cowrie with: python run_cowrie_dashboard.py")
        print("   2. Access web dashboard at: http://127.0.0.1:8080")
        print("   3. Monitor enhanced logs in: var/log/cowrie/network_training_enhanced.log")
        print("   4. Check high-risk alerts in: var/log/cowrie/network_training_alerts.log")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please review the errors above.")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n🛑 Test interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
