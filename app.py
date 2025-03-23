import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import datetime
import uuid
import json
from scanner import Scanner

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "recon_app_secret_key")

# Configure SQLite database in a file
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///recon.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Import models after db initialization to avoid circular imports
from models import Scan, ScanResult

# Initialize scanner
scanner = Scanner()

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new scan job."""
    try:
        target = request.form.get('target', '').strip()
        selected_tools = request.form.getlist('tools')
        
        if not target:
            return jsonify({'status': 'error', 'message': 'Target domain/IP is required'}), 400
            
        if not selected_tools:
            return jsonify({'status': 'error', 'message': 'At least one tool must be selected'}), 400
        
        # Generate a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create a new scan record
        new_scan = Scan(
            id=scan_id,
            target=target,
            tools=json.dumps(selected_tools),
            status="running",
            start_time=datetime.datetime.utcnow()
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan process asynchronously
        scanner.start_scan_async(scan_id, target, selected_tools)
        
        return jsonify({
            'status': 'success', 
            'message': 'Scan started successfully', 
            'scan_id': scan_id
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Error starting scan: {str(e)}'}), 500

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Get the status of a specific scan."""
    try:
        scan = Scan.query.filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
            
        return jsonify({
            'status': 'success',
            'data': {
                'scan_status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'progress': scan.progress or 0
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Error getting scan status: {str(e)}'}), 500

@app.route('/results/<scan_id>')
def results(scan_id):
    """Show results for a specific scan."""
    scan = Scan.query.filter_by(id=scan_id).first()
    
    if not scan:
        flash('Scan not found', 'danger')
        return redirect(url_for('index'))
        
    return render_template('results.html', scan=scan)

@app.route('/get_results/<scan_id>')
def get_results(scan_id):
    """Get all results for a specific scan."""
    try:
        results = ScanResult.query.filter_by(scan_id=scan_id).all()
        
        results_data = []
        for result in results:
            results_data.append({
                'tool': result.tool,
                'result_type': result.result_type,
                'data': json.loads(result.data),
                'created_at': result.created_at.isoformat()
            })
            
        return jsonify({
            'status': 'success',
            'data': results_data
        })
        
    except Exception as e:
        logger.error(f"Error getting results: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Error getting results: {str(e)}'}), 500

@app.route('/history')
def history():
    """Show scan history."""
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/download_results/<scan_id>/<format>')
def download_results(scan_id, format):
    """Download scan results in the specified format."""
    from flask import Response
    import csv
    from io import StringIO
    
    try:
        scan = Scan.query.filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
            
        results = ScanResult.query.filter_by(scan_id=scan_id).all()
        
        if format == 'json':
            results_data = []
            for result in results:
                results_data.append({
                    'tool': result.tool,
                    'result_type': result.result_type,
                    'data': json.loads(result.data),
                    'created_at': result.created_at.isoformat()
                })
                
            return jsonify({
                'scan_id': scan.id,
                'target': scan.target,
                'tools': json.loads(scan.tools),
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'results': results_data
            })
            
        elif format == 'csv':
            # Create CSV response
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Tool', 'Type', 'Value', 'Timestamp'])
            
            # Write data
            for result in results:
                data = json.loads(result.data)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            for key, value in item.items():
                                writer.writerow([result.tool, result.result_type, f"{key}: {value}", result.created_at])
                        else:
                            writer.writerow([result.tool, result.result_type, item, result.created_at])
                elif isinstance(data, dict):
                    for key, value in data.items():
                        writer.writerow([result.tool, result.result_type, f"{key}: {value}", result.created_at])
                else:
                    writer.writerow([result.tool, result.result_type, data, result.created_at])
                    
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers["Content-Disposition"] = f"attachment; filename=recon_results_{scan_id}.csv"
            return response
        else:
            return jsonify({'status': 'error', 'message': 'Unsupported format'}), 400
            
    except Exception as e:
        logger.error(f"Error downloading results: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Error downloading results: {str(e)}'}), 500

# Create tables
with app.app_context():
    db.create_all()
