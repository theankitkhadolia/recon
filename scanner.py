import threading
import logging
import json
import datetime
import time
from typing import List, Dict, Any
from utils import ToolExecutor
from app import db
from models import Scan, ScanResult

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Scanner:
    """Class to manage and execute reconnaissance scans."""
    
    def __init__(self):
        """Initialize the Scanner class."""
        self.tool_executor = ToolExecutor()
        self.active_scans = {}

    def start_scan_async(self, scan_id: str, target: str, selected_tools: List[str]) -> None:
        """
        Start a scan asynchronously.
        
        Args:
            scan_id: Unique scan identifier
            target: Target domain or IP
            selected_tools: List of tools to run
        """
        # Start a new thread for the scan
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, selected_tools)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Track the active scan
        self.active_scans[scan_id] = {
            'thread': scan_thread,
            'start_time': datetime.datetime.utcnow(),
            'target': target,
            'tools': selected_tools,
            'status': 'running'
        }
        
        logger.info(f"Started async scan {scan_id} for target {target}")

    def _run_scan(self, scan_id: str, target: str, selected_tools: List[str]) -> None:
        """
        Run the actual scan with all selected tools.
        
        Args:
            scan_id: Unique scan identifier
            target: Target domain or IP
            selected_tools: List of tools to run
        """
        logger.info(f"Running scan {scan_id} with tools: {selected_tools}")
        
        try:
            # Validate target
            if not ToolExecutor.validate_target(target):
                self._update_scan_status(scan_id, 'failed', 100)
                self._add_scan_result(scan_id, 'validation', 'error', {
                    'message': f"Invalid target: {target}"
                })
                logger.error(f"Invalid target for scan {scan_id}: {target}")
                return
            
            total_tools = len(selected_tools)
            completed_tools = 0
            
            # Define mapping of tool names to functions
            tool_functions = {
                'nmap': self._run_nmap,
                'amass': self._run_amass,
                'sublist3r': self._run_sublist3r,
                'assetfinder': self._run_assetfinder,
                'gau': self._run_gau,
                'crt': self._run_crt,
                'subfinder': self._run_subfinder,
                'shuffledns': self._run_shuffledns,
                'gospider': self._run_gospider,
                'subdomainizer': self._run_subdomainizer
            }
            
            # Run each selected tool
            for tool in selected_tools:
                if tool in tool_functions:
                    try:
                        # Update progress
                        progress = int((completed_tools / total_tools) * 100)
                        self._update_scan_status(scan_id, 'running', progress)
                        
                        # Run the tool
                        logger.info(f"Running {tool} for scan {scan_id}")
                        tool_functions[tool](scan_id, target)
                        
                        completed_tools += 1
                    except Exception as e:
                        logger.error(f"Error running {tool} for scan {scan_id}: {str(e)}")
                        self._add_scan_result(scan_id, tool, 'error', {
                            'message': f"Error: {str(e)}"
                        })
                else:
                    logger.warning(f"Unknown tool {tool} for scan {scan_id}")
                    self._add_scan_result(scan_id, tool, 'error', {
                        'message': f"Unknown tool: {tool}"
                    })
                    completed_tools += 1
            
            # Update scan status to completed
            self._update_scan_status(scan_id, 'completed', 100)
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error in scan {scan_id}: {str(e)}")
            self._update_scan_status(scan_id, 'failed', 0)
            self._add_scan_result(scan_id, 'system', 'error', {
                'message': f"Error: {str(e)}"
            })
        
        # Remove from active scans
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]

    def _update_scan_status(self, scan_id: str, status: str, progress: int) -> None:
        """
        Update the scan status in the database.
        
        Args:
            scan_id: Unique scan identifier
            status: New status (running, completed, failed)
            progress: Progress percentage (0-100)
        """
        try:
            from app import app
            with app.app_context():
                scan = Scan.query.filter_by(id=scan_id).first()
                
                if scan:
                    scan.status = status
                    scan.progress = progress
                    
                    if status in ['completed', 'failed']:
                        scan.end_time = datetime.datetime.utcnow()
                    
                    db.session.commit()
                    logger.debug(f"Updated scan {scan_id} status to {status}, progress: {progress}%")
                else:
                    logger.error(f"Scan {scan_id} not found in database when updating status")
        except Exception as e:
            logger.error(f"Error updating scan status for {scan_id}: {str(e)}")

    def _add_scan_result(self, scan_id: str, tool: str, result_type: str, data: Dict[str, Any]) -> None:
        """
        Add a scan result to the database.
        
        Args:
            scan_id: Unique scan identifier
            tool: Tool name
            result_type: Type of result (subdomain, port, url, etc.)
            data: Result data
        """
        try:
            from app import app
            with app.app_context():
                from models import ScanResult
                
                result = ScanResult(
                    scan_id=scan_id,
                    tool=tool,
                    result_type=result_type,
                    data=json.dumps(data)
                )
                
                db.session.add(result)
                db.session.commit()
                logger.debug(f"Added {tool} result for scan {scan_id}")
        except Exception as e:
            logger.error(f"Error adding scan result for {scan_id}: {str(e)}")

    def _run_nmap(self, scan_id: str, target: str) -> None:
        """Run nmap scan and save results."""
        success, results = ToolExecutor.run_nmap(target)
        
        if success:
            self._add_scan_result(scan_id, 'nmap', 'port_scan', results)
        else:
            self._add_scan_result(scan_id, 'nmap', 'error', {
                'message': 'Nmap scan failed',
                'results': results
            })

    def _run_amass(self, scan_id: str, target: str) -> None:
        """Run Amass and save results."""
        success, subdomains = ToolExecutor.run_amass(target)
        
        if success:
            self._add_scan_result(scan_id, 'amass', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'amass', 'error', {
                'message': 'Amass scan failed'
            })

    def _run_sublist3r(self, scan_id: str, target: str) -> None:
        """Run Sublist3r and save results."""
        success, subdomains = ToolExecutor.run_sublist3r(target)
        
        if success:
            self._add_scan_result(scan_id, 'sublist3r', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'sublist3r', 'error', {
                'message': 'Sublist3r scan failed'
            })

    def _run_assetfinder(self, scan_id: str, target: str) -> None:
        """Run Assetfinder and save results."""
        success, subdomains = ToolExecutor.run_assetfinder(target)
        
        if success:
            self._add_scan_result(scan_id, 'assetfinder', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'assetfinder', 'error', {
                'message': 'Assetfinder scan failed'
            })

    def _run_gau(self, scan_id: str, target: str) -> None:
        """Run GetAllUrls (GAU) and save results."""
        success, urls = ToolExecutor.run_gau(target)
        
        if success:
            self._add_scan_result(scan_id, 'gau', 'urls', urls)
        else:
            self._add_scan_result(scan_id, 'gau', 'error', {
                'message': 'GAU scan failed'
            })

    def _run_crt(self, scan_id: str, target: str) -> None:
        """Run Certificate Transparency scan and save results."""
        success, subdomains = ToolExecutor.run_crt(target)
        
        if success:
            self._add_scan_result(scan_id, 'crt', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'crt', 'error', {
                'message': 'CRT scan failed'
            })

    def _run_subfinder(self, scan_id: str, target: str) -> None:
        """Run Subfinder and save results."""
        success, subdomains = ToolExecutor.run_subfinder(target)
        
        if success:
            self._add_scan_result(scan_id, 'subfinder', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'subfinder', 'error', {
                'message': 'Subfinder scan failed'
            })

    def _run_shuffledns(self, scan_id: str, target: str) -> None:
        """Run ShuffleDNS and save results."""
        success, subdomains = ToolExecutor.run_shuffledns(target)
        
        if success:
            self._add_scan_result(scan_id, 'shuffledns', 'subdomains', subdomains)
        else:
            self._add_scan_result(scan_id, 'shuffledns', 'error', {
                'message': 'ShuffleDNS scan failed'
            })

    def _run_gospider(self, scan_id: str, target: str) -> None:
        """Run GoSpider and save results."""
        success, urls = ToolExecutor.run_gospider(target)
        
        if success:
            self._add_scan_result(scan_id, 'gospider', 'urls', urls)
        else:
            self._add_scan_result(scan_id, 'gospider', 'error', {
                'message': 'GoSpider scan failed'
            })

    def _run_subdomainizer(self, scan_id: str, target: str) -> None:
        """Run Subdomainizer and save results."""
        success, findings = ToolExecutor.run_subdomainizer(target)
        
        if success:
            self._add_scan_result(scan_id, 'subdomainizer', 'findings', findings)
        else:
            self._add_scan_result(scan_id, 'subdomainizer', 'error', {
                'message': 'Subdomainizer scan failed'
            })
