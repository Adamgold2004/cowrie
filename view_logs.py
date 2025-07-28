#!/usr/bin/env python3
"""
Cowrie Log Viewer and JSON Export Tool

This script helps you view, filter, and export your Cowrie logs in JSON format.
"""

import json
import os
import sys
from datetime import datetime
import argparse

def load_json_logs(log_file):
    """Load JSON logs from file"""
    logs = []
    if not os.path.exists(log_file):
        print(f"❌ Log file not found: {log_file}")
        return logs
    
    try:
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        log_entry = json.loads(line)
                        logs.append(log_entry)
                    except json.JSONDecodeError as e:
                        print(f"⚠️  Warning: Invalid JSON on line {line_num}: {e}")
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
    
    return logs

def filter_logs(logs, threat_level=None, src_ip=None, dst_port=None, event_type=None, limit=None):
    """Filter logs based on criteria"""
    filtered = []
    
    for log in logs:
        # Apply filters
        if threat_level and log.get('threat_level', '').lower() != threat_level.lower():
            continue
        if src_ip and log.get('src_ip') != src_ip:
            continue
        if dst_port and log.get('dst_port') != dst_port:
            continue
        if event_type and log.get('event_type') != event_type:
            continue
        
        filtered.append(log)
        
        # Apply limit
        if limit and len(filtered) >= limit:
            break
    
    return filtered

def display_logs(logs, detailed=False):
    """Display logs in a readable format"""
    if not logs:
        print("📭 No logs found matching your criteria.")
        return
    
    print(f"📊 Found {len(logs)} log entries:")
    print("=" * 80)
    
    for i, log in enumerate(logs, 1):
        timestamp = log.get('timestamp', 'Unknown')
        event_type = log.get('event_type', 'Unknown')
        src_ip = log.get('src_ip', 'Unknown')
        dst_port = log.get('dst_port', 'Unknown')
        threat_level = log.get('threat_level', 'Unknown')
        risk_score = log.get('risk_score', 0)
        
        # Color code threat levels
        threat_emoji = {
            'critical': '🔴 CRITICAL',
            'high': '🟠 HIGH',
            'medium': '🟡 MEDIUM',
            'low': '🟢 LOW'
        }
        threat_display = threat_emoji.get(threat_level.lower(), f'⚪ {threat_level.upper()}')
        
        print(f"\n📋 Entry {i}:")
        print(f"   🕐 Time: {timestamp}")
        print(f"   📡 Event: {event_type}")
        print(f"   🌐 Source IP: {src_ip}")
        print(f"   🎯 Target Port: {dst_port}")
        print(f"   ⚠️  Threat Level: {threat_display}")
        print(f"   📊 Risk Score: {risk_score}/100")
        
        if detailed:
            # Show attack indicators
            indicators = log.get('attack_indicators', [])
            if indicators:
                print(f"   🚨 Attack Indicators:")
                for indicator in indicators[:3]:  # Show first 3
                    print(f"      • {indicator}")
            
            # Show recommendations
            recommendations = log.get('recommendations', [])
            if recommendations:
                print(f"   💡 Recommendations:")
                for rec in recommendations[:2]:  # Show first 2
                    print(f"      • {rec}")
        
        print("-" * 60)

def export_logs(logs, output_file, format_type='json'):
    """Export logs to file"""
    try:
        if format_type.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(logs, f, indent=2, default=str)
            print(f"✅ Exported {len(logs)} logs to {output_file}")
        else:
            print(f"❌ Unsupported format: {format_type}")
    except Exception as e:
        print(f"❌ Error exporting logs: {e}")

def show_statistics(logs):
    """Show log statistics"""
    if not logs:
        print("📭 No logs to analyze.")
        return
    
    print(f"\n📈 LOG STATISTICS")
    print("=" * 50)
    print(f"📊 Total Events: {len(logs)}")
    
    # Threat level distribution
    threat_counts = {}
    for log in logs:
        threat = log.get('threat_level', 'unknown')
        threat_counts[threat] = threat_counts.get(threat, 0) + 1
    
    print(f"\n🚨 Threat Level Distribution:")
    for threat, count in sorted(threat_counts.items()):
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(threat, '⚪')
        print(f"   {emoji} {threat.title()}: {count}")
    
    # Top source IPs
    ip_counts = {}
    for log in logs:
        ip = log.get('src_ip', 'unknown')
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    print(f"\n🌐 Top Source IPs:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   • {ip}: {count} events")
    
    # Top target ports
    port_counts = {}
    for log in logs:
        port = log.get('dst_port', 'unknown')
        port_counts[port] = port_counts.get(port, 0) + 1
    
    print(f"\n🎯 Top Target Ports:")
    for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   • Port {port}: {count} events")

def main():
    parser = argparse.ArgumentParser(description='Cowrie Log Viewer and JSON Export Tool')
    parser.add_argument('--log-file', default='var/log/cowrie/network_training_enhanced.log',
                       help='Path to log file (default: enhanced logs)')
    parser.add_argument('--alerts-only', action='store_true',
                       help='Use alerts log file instead')
    parser.add_argument('--threat-level', choices=['critical', 'high', 'medium', 'low'],
                       help='Filter by threat level')
    parser.add_argument('--src-ip', help='Filter by source IP')
    parser.add_argument('--dst-port', type=int, help='Filter by destination port')
    parser.add_argument('--event-type', help='Filter by event type')
    parser.add_argument('--limit', type=int, help='Limit number of results')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed information')
    parser.add_argument('--stats', action='store_true',
                       help='Show statistics only')
    parser.add_argument('--export', help='Export to JSON file')
    
    args = parser.parse_args()
    
    # Determine log file
    if args.alerts_only:
        log_file = 'var/log/cowrie/network_training_alerts.log'
    else:
        log_file = args.log_file
    
    print(f"🔍 Loading logs from: {log_file}")
    logs = load_json_logs(log_file)
    
    if not logs:
        print("❌ No logs found.")
        return
    
    print(f"✅ Loaded {len(logs)} log entries")
    
    # Apply filters
    filtered_logs = filter_logs(
        logs, 
        threat_level=args.threat_level,
        src_ip=args.src_ip,
        dst_port=args.dst_port,
        event_type=args.event_type,
        limit=args.limit
    )
    
    if args.stats:
        show_statistics(filtered_logs)
    else:
        display_logs(filtered_logs, detailed=args.detailed)
        show_statistics(filtered_logs)
    
    # Export if requested
    if args.export:
        export_logs(filtered_logs, args.export)

if __name__ == "__main__":
    main()
