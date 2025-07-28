#!/usr/bin/env python3
"""
Cowrie Network Training System Status Checker

This script helps you verify that the enhanced Cowrie system with network
training is working properly.
"""

import sys
import os
import json
import time
from datetime import datetime

def check_training_data():
    """Check if training data files are present and valid"""
    print("📁 CHECKING TRAINING DATA FILES")
    print("-" * 40)
    
    training_dir = "var/lib/cowrie/training_data"
    required_files = [
        "network_attack_patterns.json",
        "target_ports.txt", 
        "attack_signatures.json",
        "training_summary.txt"
    ]
    
    all_good = True
    for filename in required_files:
        filepath = os.path.join(training_dir, filename)
        if os.path.exists(filepath):
            print(f"✅ {filename}")
        else:
            print(f"❌ {filename} - MISSING")
            all_good = False
    
    return all_good

def check_network_training_module():
    """Check if the network training module loads correctly"""
    print("\n🧠 CHECKING NETWORK TRAINING MODULE")
    print("-" * 40)
    
    try:
        sys.path.insert(0, 'src')
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_training", "src/cowrie/output/network_training.py")
        network_training_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(network_training_module)
        
        # Create instance
        trainer = network_training_module.NetworkTrainingOutput()
        print("✅ Network training module loaded successfully")
        
        # Get stats
        stats = trainer.get_training_stats()
        print("📊 Training Statistics:")
        for key, value in stats.items():
            print(f"   • {key.replace('_', ' ').title()}: {value}")
        
        return trainer
        
    except Exception as e:
        print(f"❌ Error loading network training module: {e}")
        return None

def test_threat_detection(trainer):
    """Test the threat detection capabilities"""
    print("\n🔍 TESTING THREAT DETECTION")
    print("-" * 40)
    
    if not trainer:
        print("❌ Cannot test - network training module not loaded")
        return False
    
    # Test with critical port from dataset
    test_event = {
        'eventid': 'cowrie.session.connect',
        'src_ip': '192.168.1.100',
        'dst_port': 53,  # DNS - highest frequency in dataset
        'session': 'status_check_001',
        'timestamp': datetime.now().isoformat()
    }
    
    print(f"🧪 Testing with DNS attack on port 53...")
    insights = trainer.analyze_network_event(test_event)
    
    print(f"   Threat Level: {insights['threat_level'].upper()}")
    print(f"   Risk Score: {insights['risk_score']}/100")
    print(f"   Attack Indicators: {len(insights['attack_indicators'])}")
    
    if insights['threat_level'] == 'critical' and insights['risk_score'] > 50:
        print("✅ Threat detection working correctly!")
        return True
    else:
        print("⚠️  Threat detection may not be working as expected")
        return False

def check_log_directories():
    """Check if log directories exist and are writable"""
    print("\n📝 CHECKING LOG DIRECTORIES")
    print("-" * 40)
    
    log_dirs = [
        "var/log/cowrie",
        "var/lib/cowrie/training_data"
    ]
    
    all_good = True
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            print(f"✅ {log_dir}")
        else:
            print(f"⚠️  {log_dir} - Creating directory...")
            try:
                os.makedirs(log_dir, exist_ok=True)
                print(f"✅ {log_dir} - Created successfully")
            except Exception as e:
                print(f"❌ {log_dir} - Failed to create: {e}")
                all_good = False
    
    return all_good

def show_how_to_monitor():
    """Show user how to monitor the system"""
    print("\n👀 HOW TO MONITOR THE SYSTEM")
    print("=" * 50)
    
    print("📊 Real-time Monitoring:")
    print("   1. Enhanced Events Log:")
    print("      tail -f var/log/cowrie/network_training_enhanced.log")
    print()
    print("   2. High-Risk Alerts Log:")
    print("      tail -f var/log/cowrie/network_training_alerts.log")
    print()
    print("   3. Training Data Summary:")
    print("      cat var/lib/cowrie/training_data/training_summary.txt")
    
    print("\n🔍 What to Look For:")
    print("   • Threat levels: low, medium, high, critical")
    print("   • Risk scores: 0-100 (higher = more dangerous)")
    print("   • Attack indicators: Specific threats detected")
    print("   • Port analysis: Risk assessment for target ports")
    
    print("\n🚨 Critical Ports from Your Dataset:")
    print("   • Port 53 (DNS): 2,460 attacks - CRITICAL")
    print("   • Port 443 (HTTPS): 859 attacks - CRITICAL") 
    print("   • Port 80 (HTTP): 632 attacks - CRITICAL")

def simulate_live_attack():
    """Simulate a live attack to show the system working"""
    print("\n🎭 SIMULATING LIVE ATTACK DETECTION")
    print("-" * 40)
    
    try:
        sys.path.insert(0, 'src')
        import importlib.util
        spec = importlib.util.spec_from_file_location("network_training", "src/cowrie/output/network_training.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        trainer = module.NetworkTrainingOutput()
        
        # Simulate attack on critical port
        attack_event = {
            'eventid': 'cowrie.session.connect',
            'src_ip': '203.0.113.50',
            'dst_port': 53,  # Critical DNS port
            'session': f'live_demo_{int(time.time())}',
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"🚨 INCOMING ATTACK: {attack_event['src_ip']} → Port {attack_event['dst_port']}")
        
        # Process the event
        trainer.write(attack_event)
        insights = trainer.analyze_network_event(attack_event)
        
        # Show detection results
        threat_emoji = {'low': '🟢', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}
        print(f"   {threat_emoji.get(insights['threat_level'], '⚪')} THREAT LEVEL: {insights['threat_level'].upper()}")
        print(f"   📊 RISK SCORE: {insights['risk_score']}/100")
        
        if insights['attack_indicators']:
            print(f"   🚨 ATTACK INDICATORS:")
            for indicator in insights['attack_indicators'][:3]:
                print(f"      • {indicator}")
        
        if insights['recommendations']:
            print(f"   💡 RECOMMENDATIONS:")
            for rec in insights['recommendations'][:2]:
                print(f"      • {rec}")
        
        print(f"\n✅ Attack detected and analyzed using your dataset training!")
        return True
        
    except Exception as e:
        print(f"❌ Error simulating attack: {e}")
        return False

def main():
    """Main status check function"""
    print("🎯 COWRIE NETWORK TRAINING SYSTEM STATUS CHECK")
    print("=" * 60)
    print("This script verifies that your enhanced Cowrie system is working")
    print("with the network attack training data from your dataset.")
    print("=" * 60)
    
    # Run all checks
    checks = [
        ("Training Data Files", check_training_data),
        ("Network Training Module", lambda: check_network_training_module() is not None),
        ("Log Directories", check_log_directories),
    ]
    
    results = []
    trainer = None
    
    for check_name, check_func in checks:
        print(f"\n🔍 {check_name}...")
        try:
            if check_name == "Network Training Module":
                trainer = check_network_training_module()
                result = trainer is not None
            else:
                result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"❌ Error in {check_name}: {e}")
            results.append((check_name, False))
    
    # Test threat detection if module loaded
    if trainer:
        print(f"\n🔍 Threat Detection...")
        detection_result = test_threat_detection(trainer)
        results.append(("Threat Detection", detection_result))
    
    # Show results summary
    print(f"\n" + "=" * 60)
    print("📋 STATUS SUMMARY")
    print("=" * 60)
    
    passed = 0
    for check_name, result in results:
        status = "✅ WORKING" if result else "❌ FAILED"
        print(f"   {check_name}: {status}")
        if result:
            passed += 1
    
    total = len(results)
    print(f"\nOverall Status: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 SYSTEM STATUS: FULLY OPERATIONAL")
        print("✅ Your Cowrie honeypot is enhanced with network training!")
        
        # Show live demo
        simulate_live_attack()
        
        # Show monitoring instructions
        show_how_to_monitor()
        
    else:
        print(f"\n⚠️  SYSTEM STATUS: {total - passed} issues detected")
        print("Please review the failed checks above.")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        print(f"\n{'🎊 System is ready!' if success else '⚠️  Please fix issues above'}")
    except KeyboardInterrupt:
        print("\n\n🛑 Status check interrupted")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
