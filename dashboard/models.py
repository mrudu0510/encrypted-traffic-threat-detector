# models.py - Database models for threat data

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ThreatRecord(db.Model):
    """Model for storing detected threat records."""
    __tablename__ = 'threat_records'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    threat_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    confidence = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='open')  # open, resolved, false_positive

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'protocol': self.protocol,
            'port': self.port,
            'status': self.status,
        }

    def __repr__(self):
        return f'<ThreatRecord {self.id}: {self.threat_type} ({self.severity})>'


class UploadedFile(db.Model):
    """Model for tracking uploaded traffic files."""
    __tablename__ = 'uploaded_files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    file_type = db.Column(db.String(20), nullable=True)  # csv, pcap
    status = db.Column(db.String(20), default='pending')  # pending, analyzed, failed
    threat_count = db.Column(db.Integer, default=0)
    analysis_summary = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'upload_time': self.upload_time.isoformat(),
            'file_size': self.file_size,
            'file_type': self.file_type,
            'status': self.status,
            'threat_count': self.threat_count,
            'analysis_summary': self.analysis_summary,
        }

    def __repr__(self):
        return f'<UploadedFile {self.filename}>'


class AppSettings(db.Model):
    """Model for storing application settings."""
    __tablename__ = 'app_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AppSettings {self.key}={self.value}>'
