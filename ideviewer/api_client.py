"""
API client for communicating with the IDE Viewer Portal.
"""

import os
import json
import socket
import platform
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


logger = logging.getLogger(__name__)


class APIClient:
    """Client for communicating with the IDE Viewer Portal API."""
    
    CONFIG_DIR_NAME = ".ideviewer"
    CONFIG_FILE_NAME = "config.json"
    
    def __init__(self, portal_url: str, customer_key: str):
        """
        Initialize the API client.
        
        Args:
            portal_url: Base URL of the portal (e.g., http://localhost:5000)
            customer_key: Customer UUID key for authentication
        """
        self.portal_url = portal_url.rstrip('/')
        self.customer_key = customer_key
        self.timeout = 30
    
    def _make_request(self, endpoint: str, method: str = 'GET', 
                      data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make an HTTP request to the portal API."""
        
        url = f"{self.portal_url}/api{endpoint}"
        headers = {
            'X-Customer-Key': self.customer_key,
            'Content-Type': 'application/json',
            'User-Agent': 'IDEViewer-Daemon/0.1.0',
        }
        
        body = None
        if data:
            body = json.dumps(data).encode('utf-8')
        
        request = Request(url, data=body, headers=headers, method=method)
        
        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
        except HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                error_data = json.loads(error_body)
                raise APIError(e.code, error_data.get('error', str(e)))
            except json.JSONDecodeError:
                raise APIError(e.code, str(e))
        except URLError as e:
            raise APIError(0, f"Connection failed: {e.reason}")
        except Exception as e:
            raise APIError(0, str(e))
    
    def validate_key(self) -> Dict[str, Any]:
        """
        Validate the customer key with the portal.
        
        Returns:
            Response with validation status and key details.
        
        Raises:
            APIError: If validation fails.
        """
        return self._make_request('/validate-key', method='POST', data={
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
        })
    
    def register_host(self) -> Dict[str, Any]:
        """
        Register this host with the portal.
        
        Returns:
            Response with host registration details.
        """
        return self._make_request('/register-host', method='POST', data={
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
        })
    
    def submit_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a scan report to the portal.
        
        Args:
            scan_data: The scan result data to submit.
        
        Returns:
            Response with submission confirmation.
        """
        return self._make_request('/report', method='POST', data={
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
            'scan_data': scan_data,
        })
    
    def get_pending_scan_requests(self) -> list:
        """
        Check for pending on-demand scan requests from the portal.
        
        Returns:
            List of pending scan request dictionaries.
        """
        try:
            result = self._make_request('/scan-requests/pending', method='GET')
            return result.get('requests', [])
        except APIError:
            return []
    
    def update_scan_request(self, request_id: int, status: str = None,
                            log_message: str = None, log_level: str = 'info',
                            error_message: str = None) -> Dict[str, Any]:
        """
        Update progress of an on-demand scan request.
        
        Args:
            request_id: The scan request ID.
            status: New status for the request.
            log_message: Progress log message.
            log_level: Log level (info, warning, error, success).
            error_message: Error message if scan failed.
        """
        data = {}
        if status:
            data['status'] = status
        if log_message:
            data['log_message'] = log_message
            data['log_level'] = log_level
        if error_message:
            data['error_message'] = error_message
        
        return self._make_request(f'/scan-requests/{request_id}/update', 
                                   method='POST', data=data)
    
    def send_heartbeat(self) -> Dict[str, Any]:
        """
        Send a heartbeat to the portal to indicate the daemon is alive.
        
        Returns:
            Response with heartbeat acknowledgement.
        """
        return self._make_request('/heartbeat', method='POST', data={
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
            'daemon_version': '0.1.0',
        })
    
    def send_tamper_alert(self, alert_type: str, details: str) -> Dict[str, Any]:
        """
        Send a tamper/integrity alert to the portal.
        
        Args:
            alert_type: Type of alert (uninstall_attempt, file_modified, file_deleted, daemon_stopping)
            details: Human-readable details about the event.
        """
        return self._make_request('/alert', method='POST', data={
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
            'alert_type': alert_type,
            'details': details,
        })
    
    def health_check(self) -> bool:
        """Check if the portal is reachable."""
        try:
            result = self._make_request('/health', method='GET')
            return result.get('status') == 'healthy'
        except APIError:
            return False
    
    @classmethod
    def get_config_path(cls) -> Path:
        """Get the path to the config file."""
        if platform.system() == 'Windows':
            base = Path(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')))
        else:
            base = Path.home()
        
        return base / cls.CONFIG_DIR_NAME / cls.CONFIG_FILE_NAME
    
    @classmethod
    def save_config(cls, portal_url: str, customer_key: str, scan_interval: int = 60):
        """Save configuration to disk."""
        config_path = cls.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        config = {
            'portal_url': portal_url,
            'customer_key': customer_key,
            'scan_interval_minutes': scan_interval,
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set restrictive permissions on Unix
        if platform.system() != 'Windows':
            os.chmod(config_path, 0o600)
        
        logger.info(f"Configuration saved to {config_path}")
    
    @classmethod
    def load_config(cls) -> Optional[Dict[str, str]]:
        """Load configuration from disk."""
        config_path = cls.get_config_path()
        
        if not config_path.exists():
            return None
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load config: {e}")
            return None
    
    @classmethod
    def from_config(cls) -> Optional['APIClient']:
        """Create an APIClient from saved configuration."""
        config = cls.load_config()
        if not config:
            return None
        
        portal_url = config.get('portal_url')
        customer_key = config.get('customer_key')
        
        if not portal_url or not customer_key:
            return None
        
        return cls(portal_url, customer_key)


class APIError(Exception):
    """Error from the portal API."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"API Error ({status_code}): {message}")
