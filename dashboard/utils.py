# utils.py - Helper functions for threat analysis

import os
import csv
import random
from datetime import datetime, timedelta


ALLOWED_EXTENSIONS = {'csv', 'pcap', 'pcapng'}

THREAT_TYPES = [
    'Port Scan',
    'DDoS Attack',
    'Malware Communication',
    'Data Exfiltration',
    'Brute Force',
    'Man-in-the-Middle',
    'DNS Tunneling',
    'TLS Anomaly',
    'Suspicious Beacon',
    'Command & Control',
]

SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical']


def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_severity_badge_class(severity):
    """Return Bootstrap badge class for a given severity level."""
    mapping = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'dark',
    }
    return mapping.get(severity.lower(), 'secondary')


def get_status_badge_class(status):
    """Return Bootstrap badge class for a given status."""
    mapping = {
        'open': 'danger',
        'resolved': 'success',
        'false_positive': 'secondary',
        'pending': 'warning',
        'analyzed': 'success',
        'failed': 'danger',
    }
    return mapping.get(status.lower(), 'secondary')


def analyze_csv_file(filepath):
    """
    Parse a CSV traffic file and return simulated analysis results.
    In a real deployment this would integrate with the ML detection pipeline.
    """
    results = []
    row_count = 0
    try:
        with open(filepath, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                row_count += 1
                if i >= 500:
                    break
        threat_count = max(1, int(row_count * 0.05))
        for _ in range(threat_count):
            results.append({
                'source_ip': _random_ip(),
                'destination_ip': _random_ip(),
                'threat_type': random.choice(THREAT_TYPES),
                'severity': random.choice(SEVERITY_LEVELS),
                'confidence': round(random.uniform(0.6, 0.99), 2),
                'protocol': random.choice(['TCP', 'UDP', 'TLS', 'HTTPS']),
                'port': random.choice([443, 80, 8080, 22, 53, 8443]),
                'description': 'Anomalous pattern detected in encrypted traffic.',
            })
    except Exception:
        pass
    return results, row_count


def analyze_pcap_file(filepath):
    """
    Parse a PCAP file and return simulated analysis results.
    In a real deployment this would use pyshark/scapy for deep packet inspection.
    """
    file_size = os.path.getsize(filepath)
    estimated_packets = max(10, file_size // 100)
    threat_count = max(1, int(estimated_packets * 0.03))
    results = []
    for _ in range(threat_count):
        results.append({
            'source_ip': _random_ip(),
            'destination_ip': _random_ip(),
            'threat_type': random.choice(THREAT_TYPES),
            'severity': random.choice(SEVERITY_LEVELS),
            'confidence': round(random.uniform(0.6, 0.99), 2),
            'protocol': random.choice(['TCP', 'UDP', 'TLS', 'HTTPS']),
            'port': random.choice([443, 80, 8080, 22, 53, 8443]),
            'description': 'Suspicious packet pattern identified in PCAP capture.',
        })
    return results, estimated_packets


def generate_mock_monitoring_data(num_points=20):
    """Generate mock time-series data for the real-time monitoring chart."""
    now = datetime.utcnow()
    data = []
    for i in range(num_points):
        ts = now - timedelta(seconds=(num_points - i) * 30)
        data.append({
            'timestamp': ts.strftime('%H:%M:%S'),
            'packets': random.randint(50, 500),
            'threats': random.randint(0, 10),
            'anomaly_score': round(random.uniform(0.0, 1.0), 2),
        })
    return data


def get_dashboard_stats(db_session, ThreatRecord, UploadedFile):
    """Compute summary statistics for the dashboard home page."""
    total_threats = db_session.query(ThreatRecord).count()
    critical_threats = (
        db_session.query(ThreatRecord)
        .filter(ThreatRecord.severity == 'critical')
        .count()
    )
    open_threats = (
        db_session.query(ThreatRecord)
        .filter(ThreatRecord.status == 'open')
        .count()
    )
    total_files = db_session.query(UploadedFile).count()
    recent_threats = (
        db_session.query(ThreatRecord)
        .order_by(ThreatRecord.timestamp.desc())
        .limit(5)
        .all()
    )
    severity_counts = {level: 0 for level in SEVERITY_LEVELS}
    for level in SEVERITY_LEVELS:
        severity_counts[level] = (
            db_session.query(ThreatRecord)
            .filter(ThreatRecord.severity == level)
            .count()
        )
    return {
        'total_threats': total_threats,
        'critical_threats': critical_threats,
        'open_threats': open_threats,
        'total_files': total_files,
        'recent_threats': recent_threats,
        'severity_counts': severity_counts,
    }


def _random_ip():
    """Generate a random IPv4 address."""
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))
