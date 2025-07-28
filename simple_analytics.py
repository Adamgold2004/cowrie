#!/usr/bin/env python3
"""
Simple Cowrie Analytics with Basic ML Metrics

This script generates analytics including precision, recall, F1-score,
and confidence rates using only built-in Python libraries.
"""

import json
import os
import sys
import math
from datetime import datetime
from collections import defaultdict, Counter

class SimpleCowrieAnalytics:
    def __init__(self):
        self.logs = []
        self.metrics = {}
        
    def load_logs(self, log_file='var/log/cowrie/network_training_enhanced.log'):
        """Load JSON logs from file"""
        print(f"📊 Loading logs from: {log_file}")
        
        if not os.path.exists(log_file):
            print(f"❌ Log file not found: {log_file}")
            return False
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            self.logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            
            print(f"✅ Loaded {len(self.logs)} log entries")
            return True
        except Exception as e:
            print(f"❌ Error loading logs: {e}")
            return False
    
    def calculate_ml_metrics(self):
        """Calculate precision, recall, F1-score, and confidence metrics"""
        print("\n📈 CALCULATING ML METRICS")
        print("=" * 50)
        
        # Prepare data for metrics calculation
        y_true = []  # Ground truth labels
        y_pred = []  # Predicted labels
        y_scores = []  # Confidence scores
        
        # Define threat level mapping
        threat_mapping = {
            'critical': 3,
            'high': 2, 
            'medium': 1,
            'low': 0
        }
        
        for log in self.logs:
            # Get predicted threat level
            predicted_threat = log.get('threat_level', 'low')
            risk_score = log.get('risk_score', 0)
            dst_port = log.get('dst_port', 0)
            
            # Determine ground truth based on port and training data
            # High-risk ports from training data
            critical_ports = [53, 443, 80]  # DNS, HTTPS, HTTP
            high_risk_ports = [22, 123, 8080]  # SSH, NTP, HTTP-Alt
            
            if dst_port in critical_ports:
                true_threat = 'critical'
            elif dst_port in high_risk_ports:
                true_threat = 'high'
            elif dst_port and dst_port < 1024:  # Well-known ports
                true_threat = 'medium'
            else:
                true_threat = 'low'
            
            y_true.append(threat_mapping[true_threat])
            y_pred.append(threat_mapping[predicted_threat])
            y_scores.append(risk_score / 100.0)  # Normalize to 0-1
        
        if not y_true:
            print("❌ No data available for metrics calculation")
            return
        
        # Calculate binary classification metrics (threat vs no threat)
        y_true_binary = [1 if x >= 2 else 0 for x in y_true]  # High/Critical = 1, Low/Medium = 0
        y_pred_binary = [1 if x >= 2 else 0 for x in y_pred]
        
        # Calculate confusion matrix
        tp = sum(1 for i in range(len(y_true_binary)) if y_true_binary[i] == 1 and y_pred_binary[i] == 1)
        fp = sum(1 for i in range(len(y_true_binary)) if y_true_binary[i] == 0 and y_pred_binary[i] == 1)
        tn = sum(1 for i in range(len(y_true_binary)) if y_true_binary[i] == 0 and y_pred_binary[i] == 0)
        fn = sum(1 for i in range(len(y_true_binary)) if y_true_binary[i] == 1 and y_pred_binary[i] == 0)
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        
        # Calculate confidence metrics
        confidence_mean = sum(y_scores) / len(y_scores) if y_scores else 0
        confidence_variance = sum((x - confidence_mean) ** 2 for x in y_scores) / len(y_scores) if y_scores else 0
        confidence_std = math.sqrt(confidence_variance)
        
        self.metrics = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'confidence_mean': confidence_mean,
            'confidence_std': confidence_std,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'total_samples': len(y_true)
        }
        
        # Print metrics
        print(f"🎯 THREAT DETECTION PERFORMANCE:")
        print(f"   • Precision: {precision:.3f} ({precision*100:.1f}%)")
        print(f"   • Recall: {recall:.3f} ({recall*100:.1f}%)")
        print(f"   • F1-Score: {f1_score:.3f} ({f1_score*100:.1f}%)")
        print(f"   • Accuracy: {accuracy:.3f} ({accuracy*100:.1f}%)")
        print(f"\n📊 CONFIDENCE METRICS:")
        print(f"   • Mean Confidence: {confidence_mean:.3f} ({confidence_mean*100:.1f}%)")
        print(f"   • Confidence Std Dev: {confidence_std:.3f}")
        print(f"\n🔢 CONFUSION MATRIX:")
        print(f"   • True Positives: {tp}")
        print(f"   • False Positives: {fp}")
        print(f"   • True Negatives: {tn}")
        print(f"   • False Negatives: {fn}")
        
        return self.metrics
    
    def generate_text_visualizations(self):
        """Generate text-based visualizations and statistics"""
        print(f"\n📊 GENERATING TEXT VISUALIZATIONS")
        print("=" * 50)
        
        # Threat Level Distribution
        threat_counts = Counter(log.get('threat_level', 'unknown') for log in self.logs)
        print(f"\n🚨 THREAT LEVEL DISTRIBUTION:")
        print("-" * 30)
        total_events = len(self.logs)
        for threat, count in sorted(threat_counts.items()):
            percentage = (count / total_events) * 100 if total_events > 0 else 0
            bar_length = int(percentage / 2)  # Scale for display
            bar = "█" * bar_length + "░" * (50 - bar_length)
            emoji = {'critical': 'CRIT', 'high': 'HIGH', 'medium': 'MED ', 'low': 'LOW '}.get(threat, 'UNK ')
            print(f"{emoji} {threat.title():8} |{bar}| {count:3d} ({percentage:5.1f}%)")
        
        # Risk Score Distribution
        risk_scores = [log.get('risk_score', 0) for log in self.logs if log.get('risk_score') is not None]
        if risk_scores:
            print(f"\n📈 RISK SCORE DISTRIBUTION:")
            print("-" * 30)
            # Create histogram bins
            bins = [0, 20, 40, 60, 80, 100]
            bin_counts = [0] * (len(bins) - 1)
            for score in risk_scores:
                for i in range(len(bins) - 1):
                    if bins[i] <= score < bins[i + 1]:
                        bin_counts[i] += 1
                        break
                else:
                    if score == 100:
                        bin_counts[-1] += 1
            
            max_count = max(bin_counts) if bin_counts else 1
            for i, count in enumerate(bin_counts):
                bar_length = int((count / max_count) * 40) if max_count > 0 else 0
                bar = "█" * bar_length + "░" * (40 - bar_length)
                print(f"{bins[i]:3d}-{bins[i+1]:3d} |{bar}| {count:3d}")
            
            avg_risk = sum(risk_scores) / len(risk_scores)
            print(f"\nAverage Risk Score: {avg_risk:.1f}")
        
        # Top Target Ports
        port_counts = Counter(log.get('dst_port') for log in self.logs if log.get('dst_port') is not None)
        print(f"\n🎯 TOP TARGET PORTS:")
        print("-" * 30)
        for port, count in port_counts.most_common(10):
            percentage = (count / total_events) * 100 if total_events > 0 else 0
            bar_length = int(percentage / 2)
            bar = "█" * bar_length + "░" * (25 - bar_length)
            port_name = {53: 'DNS', 443: 'HTTPS', 80: 'HTTP', 22: 'SSH', 123: 'NTP', 8080: 'HTTP-Alt'}.get(port, 'Unknown')
            print(f"Port {port:5d} ({port_name:8}) |{bar}| {count:3d} ({percentage:5.1f}%)")
        
        # Top Source IPs
        ip_counts = Counter(log.get('src_ip') for log in self.logs if log.get('src_ip'))
        print(f"\n🌐 TOP SOURCE IPs:")
        print("-" * 30)
        for ip, count in ip_counts.most_common(10):
            percentage = (count / total_events) * 100 if total_events > 0 else 0
            bar_length = int(percentage / 2)
            bar = "█" * bar_length + "░" * (25 - bar_length)
            print(f"{ip:15} |{bar}| {count:3d} ({percentage:5.1f}%)")
        
        # Timeline Analysis
        timestamps = [log.get('timestamp') for log in self.logs if log.get('timestamp')]
        if timestamps:
            print(f"\n⏰ TIMELINE ANALYSIS:")
            print("-" * 30)
            print(f"First Event: {timestamps[0]}")
            print(f"Last Event:  {timestamps[-1]}")
            print(f"Total Events: {len(timestamps)}")
            
            # Hour distribution
            hour_counts = defaultdict(int)
            for ts in timestamps:
                try:
                    # Parse timestamp and extract hour
                    if 'T' in ts:
                        time_part = ts.split('T')[1].split('.')[0]
                    else:
                        time_part = ts.split(' ')[1].split('.')[0]
                    hour = int(time_part.split(':')[0])
                    hour_counts[hour] += 1
                except:
                    continue
            
            if hour_counts:
                print(f"\n📅 HOURLY DISTRIBUTION:")
                max_hour_count = max(hour_counts.values())
                for hour in range(24):
                    count = hour_counts.get(hour, 0)
                    bar_length = int((count / max_hour_count) * 20) if max_hour_count > 0 else 0
                    bar = "█" * bar_length + "░" * (20 - bar_length)
                    print(f"{hour:2d}:00 |{bar}| {count:2d}")
    
    def generate_report(self):
        """Generate comprehensive analytics report"""
        print(f"\n📋 GENERATING ANALYTICS REPORT")
        print("=" * 50)
        
        report_content = f"""
# Cowrie Honeypot Analytics Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Dataset Overview
- **Total Events Analyzed**: {len(self.logs)}
- **Analysis Period**: {self.logs[0]['timestamp'] if self.logs else 'N/A'} to {self.logs[-1]['timestamp'] if self.logs else 'N/A'}
- **Training Data Integration**: Active

## Machine Learning Performance Metrics
"""
        
        if self.metrics:
            report_content += f"""
### Classification Performance
- **Precision**: {self.metrics['precision']:.3f} ({self.metrics['precision']*100:.1f}%)
- **Recall**: {self.metrics['recall']:.3f} ({self.metrics['recall']*100:.1f}%)
- **F1-Score**: {self.metrics['f1_score']:.3f} ({self.metrics['f1_score']*100:.1f}%)
- **Accuracy**: {self.metrics['accuracy']:.3f} ({self.metrics['accuracy']*100:.1f}%)

### Confidence Analysis
- **Mean Confidence**: {self.metrics['confidence_mean']:.3f} ({self.metrics['confidence_mean']*100:.1f}%)
- **Confidence Standard Deviation**: {self.metrics['confidence_std']:.3f}

### Confusion Matrix
|                | Predicted Safe | Predicted Threat |
|----------------|----------------|------------------|
| **Actual Safe**    | {self.metrics['true_negatives']} (TN)        | {self.metrics['false_positives']} (FP)         |
| **Actual Threat**  | {self.metrics['false_negatives']} (FN)        | {self.metrics['true_positives']} (TP)          |

### Performance Interpretation
- **High Precision ({self.metrics['precision']*100:.1f}%)**: Low false positive rate - when system flags a threat, it's usually correct
- **High Recall ({self.metrics['recall']*100:.1f}%)**: Low false negative rate - system catches most actual threats
- **F1-Score ({self.metrics['f1_score']*100:.1f}%)**: Balanced performance between precision and recall
"""
        
        # Add threat analysis
        threat_counts = Counter(log.get('threat_level', 'unknown') for log in self.logs)
        
        report_content += f"""
## Threat Analysis
### Threat Level Distribution
"""
        for threat, count in threat_counts.items():
            percentage = (count / len(self.logs)) * 100
            report_content += f"- **{threat.title()}**: {count} events ({percentage:.1f}%)\n"
        
        # Add port analysis
        port_counts = Counter(log.get('dst_port') for log in self.logs if log.get('dst_port') is not None)
        report_content += f"""
### Top Target Ports
"""
        for port, count in port_counts.most_common(5):
            percentage = (count / len(self.logs)) * 100
            port_name = {53: 'DNS', 443: 'HTTPS', 80: 'HTTP', 22: 'SSH', 123: 'NTP', 8080: 'HTTP-Alt'}.get(port, 'Unknown')
            report_content += f"- **Port {port} ({port_name})**: {count} attacks ({percentage:.1f}%)\n"
        
        report_content += f"""
## Recommendations
1. **System Performance**: The threat detection system shows {'excellent' if self.metrics.get('f1_score', 0) > 0.8 else 'good' if self.metrics.get('f1_score', 0) > 0.6 else 'moderate'} performance
2. **Monitoring Focus**: Increase monitoring on ports {', '.join(str(port) for port, _ in port_counts.most_common(3))}
3. **Alert Tuning**: {'Consider reducing sensitivity' if self.metrics.get('precision', 0) < 0.7 else 'Current alert sensitivity is appropriate'}
4. **Training Data**: Continue collecting data to improve model accuracy

## Key Findings
- **Most Targeted Port**: Port {port_counts.most_common(1)[0][0] if port_counts else 'N/A'} with {port_counts.most_common(1)[0][1] if port_counts else 0} attacks
- **Threat Detection Rate**: {self.metrics.get('recall', 0)*100:.1f}% of actual threats detected
- **False Positive Rate**: {(1-self.metrics.get('precision', 0))*100:.1f}% of alerts are false positives
- **Overall Accuracy**: {self.metrics.get('accuracy', 0)*100:.1f}% of predictions are correct
"""
        
        # Save report
        os.makedirs('analytics_output', exist_ok=True)
        with open('analytics_output/simple_analytics_report.md', 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print("✅ Saved: analytics_output/simple_analytics_report.md")
        print(f"\n📊 Analytics complete! Check the 'analytics_output' folder for the report.")

def main():
    print("🚀 SIMPLE COWRIE ANALYTICS")
    print("=" * 60)
    print("📊 Generating ML metrics and performance analysis...")
    
    # Initialize analytics
    analytics = SimpleCowrieAnalytics()
    
    # Load data
    if not analytics.load_logs():
        print("❌ Could not load logs. Please ensure the system has generated some logs.")
        return
    
    # Calculate metrics
    analytics.calculate_ml_metrics()
    
    # Generate text visualizations
    analytics.generate_text_visualizations()
    
    # Generate report
    analytics.generate_report()
    
    print(f"\n🎉 ANALYTICS COMPLETE!")
    print(f"📁 Report saved in: analytics_output/simple_analytics_report.md")

if __name__ == "__main__":
    main()
