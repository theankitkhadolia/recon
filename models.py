from app import db
from datetime import datetime
import json

class Scan(db.Model):
    """Model for recon scans."""
    id = db.Column(db.String(36), primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    tools = db.Column(db.Text, nullable=False)  # JSON string of tools used
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)  # 0-100%
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Scan {self.id} - {self.target}>'
    
    @property
    def tools_list(self):
        """Get tools as a list."""
        return json.loads(self.tools)
    
    @property
    def duration(self):
        """Get the scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def is_completed(self):
        """Check if the scan is completed."""
        return self.status == 'completed'
    
    @property
    def is_running(self):
        """Check if the scan is running."""
        return self.status == 'running'
    
    @property
    def is_failed(self):
        """Check if the scan failed."""
        return self.status == 'failed'
    
    @property
    def formatted_duration(self):
        """Get formatted duration."""
        if not self.duration:
            return "N/A"
        
        minutes, seconds = divmod(int(self.duration), 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

class ScanResult(db.Model):
    """Model for tool-specific scan results."""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan.id', ondelete='CASCADE'), nullable=False)
    tool = db.Column(db.String(50), nullable=False)  # nmap, amass, etc.
    result_type = db.Column(db.String(50), nullable=False)  # subdomain, port, url, etc.
    data = db.Column(db.Text, nullable=False)  # JSON string of results
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanResult {self.id} - {self.tool}>'
