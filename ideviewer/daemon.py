"""
Daemon runner for continuous IDE monitoring.

Features:
- IDE and extension scanning
- Plaintext secrets detection (wallet keys, API keys)
- Dependency/package inventory scanning
"""

import os
import sys
import json
import time
import signal
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable

# Handle both direct execution and package import
try:
    from .scanner import IDEScanner
    from .models import ScanResult
    from .api_client import APIClient, APIError, ScanCancelledError
    from .secrets_scanner import SecretsScanner, SecretsResult
    from .dependency_scanner import DependencyScanner, DependencyResult
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ideviewer.scanner import IDEScanner
    from ideviewer.models import ScanResult
    from ideviewer.api_client import APIClient, APIError, ScanCancelledError
    from ideviewer.secrets_scanner import SecretsScanner, SecretsResult
    from ideviewer.dependency_scanner import DependencyScanner, DependencyResult


logger = logging.getLogger(__name__)


class IDEViewerDaemon:
    """
    Daemon process for continuous IDE and extension monitoring.
    
    Features:
    - Periodic scanning at configurable intervals
    - IDE extension scanning and risk analysis
    - Plaintext secrets detection (wallet keys, API keys)
    - Dependency/package inventory
    - JSON output to file or stdout
    - Change detection and notifications
    - Graceful shutdown handling
    """
    
    def __init__(
        self,
        output_path: Optional[str] = None,
        scan_interval_minutes: int = 60,
        on_scan_complete: Optional[Callable[[ScanResult], None]] = None,
        on_change_detected: Optional[Callable[[ScanResult, ScanResult], None]] = None,
        api_client: Optional[APIClient] = None,
        scan_secrets: bool = True,
        scan_dependencies: bool = True,
    ):
        """
        Initialize the daemon.
        
        Args:
            output_path: Path to write JSON output. If None, writes to stdout.
            scan_interval_minutes: How often to scan (in minutes).
            on_scan_complete: Callback function called after each scan.
            on_change_detected: Callback for when changes are detected.
            api_client: Optional API client for portal communication.
            scan_secrets: Whether to scan for plaintext secrets.
            scan_dependencies: Whether to scan for installed dependencies.
        """
        self.output_path = output_path
        self.scan_interval = scan_interval_minutes
        self.on_scan_complete = on_scan_complete
        self.on_change_detected = on_change_detected
        self.api_client = api_client
        self.scan_secrets_enabled = scan_secrets
        self.scan_dependencies_enabled = scan_dependencies
        
        self.scanner = IDEScanner()
        self.secrets_scanner = SecretsScanner() if scan_secrets else None
        self.dependency_scanner = DependencyScanner() if scan_dependencies else None
        
        self.running = False
        self.last_result: Optional[ScanResult] = None
        self.last_secrets_result: Optional[SecretsResult] = None
        self.last_dependency_result: Optional[DependencyResult] = None
        self._shutdown_event = threading.Event()
        
        # Heartbeat interval (send heartbeat every 2 minutes)
        self.heartbeat_interval = 120  # seconds
        
        # Tamper detection: track critical files
        self._critical_files = self._get_critical_files()
        self._file_checksums = self._compute_file_checksums()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_signal)
    
    def _handle_signal(self, signum, frame):
        """Handle shutdown signals - send tamper alert before stopping."""
        signal_names = {2: 'SIGINT', 15: 'SIGTERM'}
        sig_name = signal_names.get(signum, f'signal {signum}')
        logger.info(f"Received {sig_name}, shutting down...")
        
        # Send a "daemon stopping" alert to the portal
        if self.api_client:
            try:
                self.api_client.send_tamper_alert(
                    'daemon_stopping',
                    f'Daemon received {sig_name} and is shutting down. '
                    f'This may indicate an uninstall or manual stop.'
                )
                logger.info("Shutdown alert sent to portal")
            except Exception as e:
                logger.debug(f"Failed to send shutdown alert: {e}")
        
        self.stop()
    
    def start(self, run_once: bool = False):
        """
        Start the daemon.
        
        Args:
            run_once: If True, run a single scan and exit.
        """
        logger.info("IDE Viewer Daemon starting...")
        logger.info(f"Scan interval: {self.scan_interval} minutes")
        self.running = True
        
        # Run initial scan
        self._run_scan()
        
        if run_once:
            logger.info("Single scan completed, exiting.")
            return
        
        # Use time-based scheduling instead of schedule library for reliability
        # Track when the last scan completed
        last_scan_time = datetime.now()
        scan_interval_seconds = self.scan_interval * 60
        
        logger.info(f"Scheduled scans every {self.scan_interval} minutes ({scan_interval_seconds} seconds)")
        next_scan = last_scan_time + timedelta(seconds=scan_interval_seconds)
        logger.info(f"Next scan scheduled at: {next_scan.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Run the scheduler loop
        last_heartbeat = datetime.now()
        last_tamper_check = datetime.now()
        
        while self.running and not self._shutdown_event.is_set():
            now = datetime.now()
            
            # Check if it's time for the next scan
            if now >= next_scan:
                logger.info(f"Periodic scan triggered at {now.strftime('%H:%M:%S')}")
                self._run_scan()
                last_scan_time = datetime.now()
                next_scan = last_scan_time + timedelta(seconds=scan_interval_seconds)
                logger.info(f"Next scan scheduled at: {next_scan.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Check for on-demand scan requests every poll cycle (~5 seconds)
            if self.api_client:
                self._check_on_demand_scans()

            # Send heartbeat every heartbeat_interval seconds
            if self.api_client and (now - last_heartbeat).total_seconds() >= self.heartbeat_interval:
                self._send_heartbeat()
                last_heartbeat = datetime.now()

            # Run tamper detection every 60 seconds
            if (now - last_tamper_check).total_seconds() >= 60:
                self._check_tamper()
                last_tamper_check = datetime.now()

            # Check for hook bypass events every 30 seconds
            if self.api_client and (now - getattr(self, '_last_bypass_check', datetime.min)).total_seconds() >= 30:
                self._check_hook_bypasses()
                self._last_bypass_check = datetime.now()

            # Sleep for a short interval, checking shutdown event
            self._shutdown_event.wait(timeout=5)
        
        logger.info("Daemon stopped.")
    
    def stop(self):
        """Stop the daemon."""
        self.running = False
        self._shutdown_event.set()
    
    # ==========================================
    # Heartbeat
    # ==========================================
    
    def _send_heartbeat(self):
        """Send a heartbeat to the portal."""
        if not self.api_client:
            return
        try:
            self.api_client.send_heartbeat()
            logger.debug("Heartbeat sent to portal")
        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")
    
    # ==========================================
    # Tamper Detection
    # ==========================================
    
    def _get_critical_files(self) -> list:
        """Get list of critical daemon files to monitor for tampering."""
        import sys as _sys
        files = []
        
        # The daemon executable itself
        executable = Path(_sys.executable)
        if executable.exists():
            files.append(executable)
        
        # Platform-specific daemon files
        if _sys.platform == 'darwin':
            # macOS LaunchDaemon plist
            plist = Path('/Library/LaunchDaemons/com.ideviewer.daemon.plist')
            if plist.exists():
                files.append(plist)
            # Installed binary
            binary = Path('/usr/local/bin/ideviewer')
            if binary.exists():
                files.append(binary)
            # Uninstaller
            uninstaller = Path('/usr/local/bin/ideviewer-uninstall')
            if uninstaller.exists():
                files.append(uninstaller)
        elif _sys.platform == 'win32':
            # Windows service binary
            binary = Path(os.environ.get('ProgramFiles', 'C:\\Program Files')) / 'IDEViewer' / 'ideviewer.exe'
            if binary.exists():
                files.append(binary)
        else:
            # Linux .deb installed binary
            binary = Path('/usr/local/bin/ideviewer')
            if binary.exists():
                files.append(binary)
            # Systemd service file
            service = Path('/etc/systemd/system/ideviewer.service')
            if service.exists():
                files.append(service)
        
        # Config file
        config_path = APIClient.get_config_path()
        if config_path.exists():
            files.append(config_path)
        
        return files
    
    def _compute_file_checksums(self) -> dict:
        """Compute checksums of critical files for tamper detection."""
        import hashlib
        checksums = {}
        for f in self._critical_files:
            try:
                if f.exists():
                    checksums[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()
            except Exception:
                pass
        return checksums
    
    def _check_tamper(self):
        """Check for tampering of critical daemon files."""
        import hashlib
        
        for file_path in self._critical_files:
            path_str = str(file_path)
            
            if not file_path.exists():
                # File was deleted
                if path_str in self._file_checksums:
                    logger.warning(f"TAMPER: Critical file deleted: {path_str}")
                    if self.api_client:
                        try:
                            self.api_client.send_tamper_alert(
                                'file_deleted',
                                f'Critical daemon file was deleted: {path_str}. '
                                f'This may indicate an uninstall attempt.'
                            )
                        except Exception as e:
                            logger.debug(f"Failed to send tamper alert: {e}")
                    # Remove from checksums so we don't re-alert
                    del self._file_checksums[path_str]
            else:
                try:
                    current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
                    stored_hash = self._file_checksums.get(path_str)
                    
                    if stored_hash and current_hash != stored_hash:
                        logger.warning(f"TAMPER: Critical file modified: {path_str}")
                        if self.api_client:
                            try:
                                self.api_client.send_tamper_alert(
                                    'file_modified',
                                    f'Critical daemon file was modified: {path_str}. '
                                    f'Expected hash: {stored_hash[:16]}..., '
                                    f'current: {current_hash[:16]}...'
                                )
                            except Exception as e:
                                logger.debug(f"Failed to send tamper alert: {e}")
                        # Update the stored hash so we don't re-alert continuously
                        self._file_checksums[path_str] = current_hash
                    elif not stored_hash:
                        # New file appeared, just track it
                        self._file_checksums[path_str] = current_hash
                except Exception:
                    pass

    # ==========================================
    # Hook Bypass Detection
    # ==========================================

    def _check_hook_bypasses(self):
        """Check for pending hook bypass events and report them to the portal."""
        if not self.api_client:
            return

        bypasses_file = Path.home() / '.ideviewer' / 'bypasses' / 'pending.jsonl'
        if not bypasses_file.exists():
            return

        try:
            with open(bypasses_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            if not lines:
                return

            logger.info(f"Found {len(lines)} hook bypass event(s) to report")

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    bypass_data = json.loads(line)
                    self.api_client.send_hook_bypass(bypass_data)
                    logger.info(f"Reported hook bypass: {bypass_data.get('commit_hash', 'unknown')[:8]}")
                except json.JSONDecodeError:
                    logger.warning(f"Invalid bypass event JSON: {line[:100]}")
                except Exception as e:
                    logger.debug(f"Failed to report hook bypass: {e}")

            # Remove the file after processing
            bypasses_file.unlink(missing_ok=True)

        except Exception as e:
            logger.debug(f"Error checking hook bypasses: {e}")

    def _run_scan(self):
        """Run all scans and handle the results."""
        logger.info(f"Starting scan at {datetime.now().isoformat()}")
        
        try:
            # Run IDE/extension scan
            result = self.scanner.scan()
            
            # Run secrets scan
            secrets_result = None
            if self.secrets_scanner:
                logger.info("Running secrets scan...")
                secrets_result = self.secrets_scanner.scan()
                self.last_secrets_result = secrets_result
                if secrets_result.findings:
                    logger.warning(
                        f"Found {len(secrets_result.findings)} plaintext secrets!"
                    )
            
            # Run dependency scan
            dependency_result = None
            if self.dependency_scanner:
                logger.info("Running dependency scan...")
                dependency_result = self.dependency_scanner.scan()
                self.last_dependency_result = dependency_result
                logger.info(
                    f"Found {len(dependency_result.packages)} packages across "
                    f"{len(dependency_result.package_managers_found)} package managers"
                )
            
            # Check for changes
            if self.last_result and self.on_change_detected:
                if self._has_changes(self.last_result, result):
                    self.on_change_detected(self.last_result, result)
            
            self.last_result = result
            
            # Output results locally
            self._output_result(result, secrets_result, dependency_result)
            
            # Send to portal if API client is configured
            if self.api_client:
                self._send_to_portal(result, secrets_result, dependency_result)
            
            # Callback
            if self.on_scan_complete:
                self.on_scan_complete(result)
            
            logger.info(
                f"Scan completed: {len(result.ides)} IDEs, "
                f"{sum(len(ide.extensions) for ide in result.ides)} extensions"
            )
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
    
    def _check_on_demand_scans(self):
        """Check for and execute on-demand scan requests from the portal."""
        try:
            pending = self.api_client.get_pending_scan_requests()
            if not pending:
                return
            
            import socket as sock
            my_hostname = sock.gethostname()
            
            for req in pending:
                request_id = req.get('id')
                if not request_id:
                    continue
                
                logger.info(f"Processing on-demand scan request #{request_id}")
                self._execute_on_demand_scan(request_id)
                
        except Exception as e:
            logger.debug(f"Error checking on-demand scans: {e}")
    
    def _execute_on_demand_scan(self, request_id: int):
        """Execute a single on-demand scan with progress reporting."""
        update = self.api_client.update_scan_request
        
        try:
            # Step 1: Acknowledge
            update(request_id, status='connecting',
                   log_message='Daemon received scan request, establishing connection...')
            
            update(request_id, log_message=f'Connected to daemon on host', 
                   log_level='success')
            
            # Step 2: IDE scanning
            update(request_id, status='scanning_ides',
                   log_message='Starting IDE and extension scan...')
            
            result = self.scanner.scan()
            
            for ide in result.ides:
                ext_count = len(ide.extensions)
                dangerous = sum(1 for e in ide.extensions
                              for p in e.permissions if getattr(p, 'is_dangerous', False))
                update(request_id,
                       log_message=f'Found {ide.name} v{ide.version} — {ext_count} extensions ({dangerous} flagged)')
            
            update(request_id, 
                   log_message=f'IDE scan complete: {len(result.ides)} IDEs, '
                   f'{sum(len(ide.extensions) for ide in result.ides)} total extensions',
                   log_level='success')
            
            # Step 3: Secrets scanning
            secrets_result = None
            if self.secrets_scanner:
                update(request_id, status='scanning_secrets',
                       log_message='Starting plaintext secrets scan...')
                
                secrets_result = self.secrets_scanner.scan()
                self.last_secrets_result = secrets_result
                
                if secrets_result.findings:
                    update(request_id,
                           log_message=f'WARNING: Found {len(secrets_result.findings)} '
                           f'plaintext secret(s)!',
                           log_level='warning')
                    for finding in secrets_result.findings:
                        update(request_id,
                               log_message=f'  {finding.secret_type} in {finding.file_path}',
                               log_level='warning')
                else:
                    update(request_id,
                           log_message='No plaintext secrets detected',
                           log_level='success')
            
            # Step 4: Package scanning
            dependency_result = None
            if self.dependency_scanner:
                update(request_id, status='scanning_packages',
                       log_message='Starting package/dependency scan...')
                
                dependency_result = self.dependency_scanner.scan()
                self.last_dependency_result = dependency_result
                
                for mgr in dependency_result.package_managers_found:
                    count = sum(1 for p in dependency_result.packages 
                              if p.package_manager == mgr)
                    update(request_id,
                           log_message=f'Found {count} {mgr} packages')
                
                # Report packages with lifecycle hooks
                hooks_count = sum(1 for p in dependency_result.packages 
                                 if p.lifecycle_hooks)
                if hooks_count:
                    update(request_id,
                           log_message=f'WARNING: {hooks_count} npm package(s) '
                           f'with lifecycle hooks (preinstall/postinstall)',
                           log_level='warning')
                
                update(request_id,
                       log_message=f'Package scan complete: {len(dependency_result.packages)} '
                       f'packages across {len(dependency_result.package_managers_found)} '
                       f'package managers',
                       log_level='success')
            
            # Step 5: Send results to portal
            update(request_id, log_message='Submitting scan results to portal...')
            
            self.last_result = result
            self._send_to_portal(result, secrets_result, dependency_result)
            
            update(request_id, status='completed',
                   log_message='On-demand scan completed successfully',
                   log_level='success')
            
            logger.info(f"On-demand scan #{request_id} completed successfully")
            
        except ScanCancelledError:
            logger.info(f"On-demand scan #{request_id} was cancelled by user")

        except Exception as e:
            logger.error(f"On-demand scan #{request_id} failed: {e}")
            try:
                update(request_id, status='failed',
                       log_message=f'Scan failed: {str(e)}',
                       log_level='error',
                       error_message=str(e))
            except Exception:
                pass
    
    def _send_to_portal(self, result: ScanResult, 
                        secrets_result: Optional[SecretsResult] = None,
                        dependency_result: Optional[DependencyResult] = None):
        """Send scan results to the portal."""
        if not self.api_client:
            return
        
        try:
            # Build combined scan data
            scan_data = result.to_dict()
            
            # Add secrets findings (without actual secret values)
            if secrets_result:
                scan_data['secrets'] = secrets_result.to_dict()
            
            # Add dependency data
            if dependency_result:
                scan_data['dependencies'] = dependency_result.to_dict()
            
            response = self.api_client.submit_report(scan_data)
            logger.info(
                f"Report submitted to portal: {response.get('stats', {})}"
            )
        except APIError as e:
            logger.error(f"Failed to submit report to portal: {e.message}")
        except Exception as e:
            logger.error(f"Unexpected error submitting to portal: {e}")
    
    def _output_result(self, result: ScanResult,
                       secrets_result: Optional[SecretsResult] = None,
                       dependency_result: Optional[DependencyResult] = None):
        """Output scan result to file or stdout."""
        # Build combined output
        output_data = result.to_dict()
        
        if secrets_result:
            output_data['secrets'] = secrets_result.to_dict()
        
        if dependency_result:
            output_data['dependencies'] = dependency_result.to_dict()
        
        output = json.dumps(output_data, indent=2, default=str)
        
        if self.output_path:
            output_file = Path(self.output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)
            
            logger.info(f"Results written to {self.output_path}")
        else:
            print(output)
    
    def _has_changes(self, old: ScanResult, new: ScanResult) -> bool:
        """Check if there are changes between two scan results."""
        # Compare IDE counts
        if len(old.ides) != len(new.ides):
            return True
        
        # Compare extension counts per IDE
        old_ext_counts = {ide.name: len(ide.extensions) for ide in old.ides}
        new_ext_counts = {ide.name: len(ide.extensions) for ide in new.ides}
        
        if old_ext_counts != new_ext_counts:
            return True
        
        # Compare extension IDs
        old_ext_ids = set()
        new_ext_ids = set()
        
        for ide in old.ides:
            for ext in ide.extensions:
                old_ext_ids.add(f"{ide.name}:{ext.id}")
        
        for ide in new.ides:
            for ext in ide.extensions:
                new_ext_ids.add(f"{ide.name}:{ext.id}")
        
        return old_ext_ids != new_ext_ids


def create_pid_file(pid_file: str) -> bool:
    """Create a PID file for the daemon."""
    pid_path = Path(pid_file)
    
    # Check if already running
    if pid_path.exists():
        try:
            with open(pid_path, "r") as f:
                old_pid = int(f.read().strip())
            
            # Check if process is still running
            try:
                os.kill(old_pid, 0)
                return False  # Process is still running
            except OSError:
                pass  # Process not running, we can continue
        except (ValueError, IOError):
            pass
    
    # Write new PID file
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))
    
    return True


def remove_pid_file(pid_file: str):
    """Remove the PID file."""
    try:
        os.remove(pid_file)
    except OSError:
        pass


def daemonize():
    """
    Daemonize the process (Unix only).
    
    Uses double-fork technique to properly daemonize.
    """
    if sys.platform == "win32":
        # Windows doesn't support fork, run in foreground
        return
    
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error(f"First fork failed: {e}")
        sys.exit(1)
    
    # Decouple from parent
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error(f"Second fork failed: {e}")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open("/dev/null", "r") as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    
    with open("/dev/null", "a+") as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())
