
# Cowrie Honeypot Analytics Report
Generated on: 2025-07-26 17:31:33

## Dataset Overview
- **Total Events Analyzed**: 11
- **Analysis Period**: 2025-07-26 14:34:16 to 2025-07-26 14:56:02
- **Training Data Integration**: Active

## Machine Learning Performance Metrics

### Classification Performance
- **Precision**: 1.000 (100.0%)
- **Recall**: 1.000 (100.0%)
- **F1-Score**: 1.000 (100.0%)
- **Accuracy**: 1.000 (100.0%)

### Confidence Analysis
- **Mean Confidence**: 0.605 (60.5%)
- **Confidence Standard Deviation**: 0.156

### Confusion Matrix
|                | Predicted Safe | Predicted Threat |
|----------------|----------------|------------------|
| **Actual Safe**    | 0 (TN)        | 0 (FP)         |
| **Actual Threat**  | 0 (FN)        | 11 (TP)          |

### Performance Interpretation
- **High Precision (100.0%)**: Low false positive rate - when system flags a threat, it's usually correct
- **High Recall (100.0%)**: Low false negative rate - system catches most actual threats
- **F1-Score (100.0%)**: Balanced performance between precision and recall

## Threat Analysis
### Threat Level Distribution
- **Critical**: 8 events (72.7%)
- **High**: 3 events (27.3%)

### Top Target Ports
- **Port 53 (DNS)**: 5 attacks (45.5%)
- **Port 443 (HTTPS)**: 3 attacks (27.3%)
- **Port 22 (SSH)**: 3 attacks (27.3%)

## Recommendations
1. **System Performance**: The threat detection system shows excellent performance
2. **Monitoring Focus**: Increase monitoring on ports 53, 443, 22
3. **Alert Tuning**: Current alert sensitivity is appropriate
4. **Training Data**: Continue collecting data to improve model accuracy

## Key Findings
- **Most Targeted Port**: Port 53 with 5 attacks
- **Threat Detection Rate**: 100.0% of actual threats detected
- **False Positive Rate**: 0.0% of alerts are false positives
- **Overall Accuracy**: 100.0% of predictions are correct
