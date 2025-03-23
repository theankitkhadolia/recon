import re
import subprocess
import shlex
import logging
import json
import os
from typing import List, Dict, Union, Tuple, Optional, Any
import tempfile

# Setup logging
logger = logging.getLogger(__name__)

class ToolExecutor:
    """Class to handle the execution of reconnaissance tools."""

    @staticmethod
    def validate_target(target: str) -> bool:
        """
        Validate if the target is a valid domain or IP address.
        
        Args:
            target: Domain or IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Domain name validation - simple check
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        # IP address validation
        ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        
        if re.match(domain_pattern, target):
            return True
        
        if re.match(ip_pattern, target):
            # Check if each octet is in range 0-255
            octets = target.split('.')
            for octet in octets:
                if int(octet) > 255:
                    return False
            return True
            
        return False

    @staticmethod
    def run_command(command: str, timeout: int = 300) -> Tuple[bool, str]:
        """
        Run a shell command and return the output.
        
        Args:
            command: Command to run
            timeout: Command timeout in seconds
            
        Returns:
            tuple: (success (bool), output (str))
        """
        try:
            # Use shlex to properly handle command args
            args = shlex.split(command)
            
            # Run the command with a timeout
            result = subprocess.run(
                args, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                logger.error(f"Command failed: {command}")
                logger.error(f"Error: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, f"Command timed out after {timeout} seconds"
            
        except Exception as e:
            logger.error(f"Error running command '{command}': {str(e)}")
            return False, f"Error: {str(e)}"

    @staticmethod
    def run_nmap(target: str, flags: str = "-sV -sS -T4") -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Run nmap scan against the target.
        
        Args:
            target: Target domain or IP
            flags: Nmap flags
            
        Returns:
            tuple: (success (bool), results (list))
        """
        # Create temporary file for output
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')
        temp_file.close()
        
        command = f"nmap {flags} -oX {temp_file.name} {target}"
        success, output = ToolExecutor.run_command(command)
        
        results = []
        if success:
            try:
                # Parse XML output
                import xml.etree.ElementTree as ET
                tree = ET.parse(temp_file.name)
                root = tree.getroot()
                
                # Process hosts
                for host in root.findall('.//host'):
                    host_data = {'ip': '', 'ports': []}
                    
                    # Get IP address
                    address = host.find('.//address')
                    if address is not None and address.attrib.get('addrtype') == 'ipv4':
                        host_data['ip'] = address.attrib.get('addr', '')
                    
                    # Get ports
                    for port in host.findall('.//port'):
                        port_data = {
                            'port': port.attrib.get('portid', ''),
                            'protocol': port.attrib.get('protocol', ''),
                            'state': '',
                            'service': '',
                            'version': ''
                        }
                        
                        # Get state
                        state = port.find('state')
                        if state is not None:
                            port_data['state'] = state.attrib.get('state', '')
                        
                        # Get service details
                        service = port.find('service')
                        if service is not None:
                            port_data['service'] = service.attrib.get('name', '')
                            port_data['version'] = service.attrib.get('product', '')
                            if 'version' in service.attrib:
                                port_data['version'] += f" {service.attrib.get('version', '')}"
                        
                        host_data['ports'].append(port_data)
                    
                    results.append(host_data)
                    
            except Exception as e:
                logger.error(f"Error parsing nmap output: {str(e)}")
                success = False
                results = []
        
        # Clean up temp file
        try:
            os.unlink(temp_file.name)
        except:
            pass
            
        return success, results

    @staticmethod
    def run_amass(target: str, timeout: int = 600) -> Tuple[bool, List[str]]:
        """
        Run Amass for subdomain enumeration.
        
        Args:
            target: Target domain
            timeout: Command timeout in seconds
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        command = f"amass enum -d {target}"
        success, output = ToolExecutor.run_command(command, timeout)
        
        if success:
            # Parse output for subdomains
            subdomains = []
            for line in output.splitlines():
                if target in line and not line.startswith('#'):
                    subdomain = line.strip()
                    if subdomain:
                        subdomains.append(subdomain)
            return True, subdomains
        else:
            return False, []

    @staticmethod
    def run_sublist3r(target: str) -> Tuple[bool, List[str]]:
        """
        Run Sublist3r for subdomain enumeration.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        command = f"sublist3r -d {target} -o sublist3r_output.txt"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            subdomains = []
            
            try:
                # Try to read from the output file
                with open("sublist3r_output.txt", "r") as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            subdomains.append(subdomain)
                
                # Delete the temporary file
                os.remove("sublist3r_output.txt")
            except:
                # If we can't read the file, parse from the output
                for line in output.splitlines():
                    if target in line and not line.startswith('['):
                        subdomain = line.strip()
                        if subdomain:
                            subdomains.append(subdomain)
            
            return True, subdomains
        else:
            return False, []

    @staticmethod
    def run_assetfinder(target: str) -> Tuple[bool, List[str]]:
        """
        Run Assetfinder for subdomain enumeration.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        command = f"assetfinder --subs-only {target}"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            # Parse output for subdomains
            subdomains = []
            for line in output.splitlines():
                subdomain = line.strip()
                if subdomain and target in subdomain:
                    subdomains.append(subdomain)
            return True, subdomains
        else:
            return False, []

    @staticmethod
    def run_gau(target: str) -> Tuple[bool, List[str]]:
        """
        Run GetAllUrls (GAU) to discover URLs.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), urls (list))
        """
        command = f"gau {target}"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            # Parse output for URLs
            urls = []
            for line in output.splitlines():
                url = line.strip()
                if url:
                    urls.append(url)
            return True, urls
        else:
            return False, []

    @staticmethod
    def run_crt(target: str) -> Tuple[bool, List[str]]:
        """
        Search Certificate Transparency Logs for subdomains.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        # Using curl to access crt.sh website
        command = f"curl -s 'https://crt.sh/?q=%25.{target}&output=json'"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            try:
                data = json.loads(output)
                subdomains = set()
                
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    # Split by newlines and handle multiple domains
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and subdomain != target and subdomain.endswith(target):
                            # Remove wildcard
                            subdomain = subdomain.replace('*.', '')
                            subdomains.add(subdomain)
                
                return True, list(subdomains)
            except Exception as e:
                logger.error(f"Error parsing crt.sh output: {str(e)}")
                return False, []
        else:
            return False, []

    @staticmethod
    def run_subfinder(target: str) -> Tuple[bool, List[str]]:
        """
        Run Subfinder for subdomain enumeration.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        command = f"subfinder -d {target}"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            # Parse output for subdomains
            subdomains = []
            for line in output.splitlines():
                subdomain = line.strip()
                if subdomain:
                    subdomains.append(subdomain)
            return True, subdomains
        else:
            return False, []

    @staticmethod
    def run_shuffledns(target: str) -> Tuple[bool, List[str]]:
        """
        Run ShuffleDNS for subdomain enumeration.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), subdomains (list))
        """
        # Create temporary files for output and wordlist
        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_output.close()
        
        # Check if the resolvers file exists, if not create it
        resolvers_file = "resolvers.txt"
        if not os.path.exists(resolvers_file):
            with open(resolvers_file, "w") as f:
                f.write("1.1.1.1\n8.8.8.8\n9.9.9.9\n208.67.222.222")
        
        # Check if we have a wordlist, if not use a simple example
        wordlist_file = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if not os.path.exists(wordlist_file):
            wordlist_file = "wordlist.txt"
            if not os.path.exists(wordlist_file):
                with open(wordlist_file, "w") as f:
                    f.write("www\nadmin\nmail\nblog\ndev\ntest\nstaging")
        
        command = f"shuffledns -d {target} -w {wordlist_file} -r {resolvers_file} -o {temp_output.name}"
        success, output = ToolExecutor.run_command(command)
        
        subdomains = []
        if success:
            try:
                # Read subdomains from the output file
                with open(temp_output.name, "r") as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            subdomains.append(subdomain)
            except Exception as e:
                logger.error(f"Error reading ShuffleDNS output: {str(e)}")
                success = False
        
        # Clean up temp files
        try:
            os.unlink(temp_output.name)
        except:
            pass
            
        return success, subdomains

    @staticmethod
    def run_gospider(target: str) -> Tuple[bool, List[str]]:
        """
        Run GoSpider for crawling URLs.
        
        Args:
            target: Target domain or URL
            
        Returns:
            tuple: (success (bool), urls (list))
        """
        # Ensure the target has http/https prefix
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        command = f"gospider -s {target} -d 2 -c 5 -t 5"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            # Parse output for URLs
            urls = []
            for line in output.splitlines():
                if "[url]" in line:
                    url = line.split("[url]")[1].strip()
                    if url:
                        urls.append(url)
            return True, urls
        else:
            return False, []

    @staticmethod
    def run_subdomainizer(target: str) -> Tuple[bool, List[str]]:
        """
        Run Subdomainizer to find subdomains and secrets.
        
        Args:
            target: Target domain
            
        Returns:
            tuple: (success (bool), findings (list))
        """
        # Ensure the target has http/https prefix
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        command = f"python3 SubDomainizer.py -u {target}"
        success, output = ToolExecutor.run_command(command)
        
        if success:
            # Parse output for findings
            findings = []
            
            current_section = None
            for line in output.splitlines():
                line = line.strip()
                
                if "Subdomain Discovery Started" in line:
                    current_section = "subdomains"
                    continue
                elif "Domain Discovery Completed" in line:
                    current_section = None
                    continue
                elif "Scanning for secrets" in line:
                    current_section = "secrets"
                    continue
                elif "Scanning for secrets completed" in line:
                    current_section = None
                    continue
                
                if current_section == "subdomains" and line and not line.startswith(("[+]", "[*]")):
                    findings.append({"type": "subdomain", "value": line})
                elif current_section == "secrets" and "Found" in line:
                    findings.append({"type": "secret", "value": line})
            
            return True, findings
        else:
            return False, []
