"""
Command-line interface for IDE Viewer.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich import box

# Handle both direct execution and package import
try:
    from . import __version__
    from .scanner import IDEScanner
    from .daemon import IDEViewerDaemon, create_pid_file, remove_pid_file, daemonize
    from .models import ScanResult
    from .api_client import APIClient, APIError
    from .secrets_scanner import SecretsScanner
    from .dependency_scanner import DependencyScanner
    from .sarif_formatter import scan_result_to_sarif, secrets_result_to_sarif, to_sarif_json
except ImportError:
    # Direct execution - add parent to path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ideviewer import __version__
    from ideviewer.scanner import IDEScanner
    from ideviewer.daemon import IDEViewerDaemon, create_pid_file, remove_pid_file, daemonize
    from ideviewer.models import ScanResult
    from ideviewer.api_client import APIClient, APIError
    from ideviewer.secrets_scanner import SecretsScanner
    from ideviewer.dependency_scanner import DependencyScanner
    from ideviewer.sarif_formatter import scan_result_to_sarif, secrets_result_to_sarif, to_sarif_json


console = Console()


def _get_default_log_dir() -> Path:
    """Get the default log directory for the platform."""
    if sys.platform == 'darwin':
        return Path('/var/log/ideviewer')
    elif sys.platform == 'win32':
        return Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'IDEViewer' / 'logs'
    else:
        return Path('/var/log/ideviewer')


def setup_logging(verbose: bool, log_file: Optional[str] = None, daemon_mode: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    handlers = []

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    elif daemon_mode:
        # Always log to file when running as a daemon (not foreground)
        log_dir = _get_default_log_dir()
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(log_dir / 'daemon.log'))
        except PermissionError:
            # Fall back to user-level log dir
            log_dir = Path.home() / '.ideviewer' / 'logs'
            log_dir.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(log_dir / 'daemon.log'))

    # Always include stderr for foreground mode
    if not daemon_mode or not handlers:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


@click.group()
@click.version_option(version=__version__)
def cli():
    """IDE Viewer - Cross-platform IDE and Extension Scanner"""
    pass


def send_to_portal(scan_data: dict, secrets_data: dict = None, deps_data: dict = None) -> bool:
    """Send scan results to the portal using saved configuration."""
    config = APIClient.load_config()
    if not config:
        console.print("[red]✗ No portal configuration found. Run 'ideviewer register' first.[/]")
        return False
    
    try:
        api_client = APIClient(config.get('portal_url'), config.get('customer_key'))
        
        # Add secrets and dependencies if provided
        if secrets_data:
            scan_data['secrets'] = secrets_data
        if deps_data:
            scan_data['dependencies'] = deps_data
        
        response = api_client.submit_report(scan_data)
        if response.get('success'):
            stats = response.get('stats', {})
            console.print(f"[green]✓ Report sent to portal[/]")
            console.print(f"  [dim]IDEs: {stats.get('total_ides', 0)}, "
                         f"Extensions: {stats.get('total_extensions', 0)}, "
                         f"Secrets: {stats.get('secrets_found', 0)}, "
                         f"Packages: {stats.get('packages_found', 0)}[/]")
            return True
        else:
            console.print(f"[red]✗ Portal rejected report: {response.get('error')}[/]")
            return False
    except APIError as e:
        console.print(f"[red]✗ Portal error: {e.message}[/]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Failed to send to portal: {e}[/]")
        return False


def _scan_staged_secrets(use_exit_code: bool):
    """Scan only git-staged .env files for secrets (used by pre-commit hook)."""
    import subprocess as _sp

    # Get staged file list
    try:
        result = _sp.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            console.print("[yellow]Not in a git repository or git error[/]")
            sys.exit(0)
        staged_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except FileNotFoundError:
        console.print("[yellow]git is not installed[/]")
        sys.exit(0)
    except _sp.TimeoutExpired:
        console.print("[yellow]git command timed out[/]")
        sys.exit(0)

    if not staged_files:
        sys.exit(0)

    # Filter to .env files matching SecretsScanner.TARGET_FILES
    target_files = set(SecretsScanner.TARGET_FILES)
    env_files = [f for f in staged_files if Path(f).name in target_files]

    if not env_files:
        sys.exit(0)

    # Scan each staged .env file using git show to get staged content
    scanner = SecretsScanner()
    all_findings = []

    for filepath in env_files:
        try:
            result = _sp.run(
                ["git", "show", f":{filepath}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                continue

            content = result.stdout
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if not value:
                    continue

                finding = scanner._check_eth_private_key(Path(filepath), key, value, line_num)
                if not finding:
                    finding = scanner._check_mnemonic(Path(filepath), key, value, line_num)
                if not finding:
                    finding = scanner._check_aws_credentials(Path(filepath), key, value, line_num)

                if finding:
                    all_findings.append(finding)

        except (_sp.TimeoutExpired, Exception) as e:
            console.print(f"[yellow]Warning: could not read staged {filepath}: {e}[/]")

    if all_findings:
        console.print(f"[bold red]Found {len(all_findings)} secret(s) in staged files:[/]")
        for f in all_findings:
            severity_color = "red" if f.severity == "critical" else "yellow"
            console.print(
                f"  [{severity_color}]{f.severity.upper()}[/] "
                f"{f.secret_type.replace('_', ' ').title()} "
                f"({f.variable_name}) in {f.file_path}:{f.line_number}"
            )
        if use_exit_code:
            sys.exit(1)
    else:
        sys.exit(0)


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--output-sarif", is_flag=True, help="Output in SARIF v2.1.0 format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--ide", "-i", multiple=True, help="Filter by IDE type (can be used multiple times)")
@click.option("--portal", is_flag=True, help="Send results to the portal")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(output_json: bool, output_sarif: bool, output: Optional[str], ide: tuple, portal: bool, verbose: bool):
    """Scan for installed IDEs and their extensions."""
    setup_logging(verbose)

    with console.status("[bold cyan]Scanning for IDEs...[/]"):
        scanner = IDEScanner()
        result = scanner.scan(list(ide) if ide else None)

    # Also run secrets and dependency scans if sending to portal
    secrets_result = None
    deps_result = None
    if portal:
        with console.status("[bold cyan]Scanning for secrets...[/]"):
            secrets_scanner = SecretsScanner()
            secrets_result = secrets_scanner.scan()

        with console.status("[bold cyan]Scanning for packages...[/]"):
            dep_scanner = DependencyScanner()
            deps_result = dep_scanner.scan()

    if output_sarif:
        sarif_data = scan_result_to_sarif(result.to_dict(), version=__version__)
        sarif_output = to_sarif_json(sarif_data)
        if output:
            Path(output).write_text(sarif_output)
            console.print(f"[green]SARIF results written to {output}[/]")
        else:
            print(sarif_output)
    elif output_json or output:
        output_data = json.dumps(result.to_dict(), indent=2, default=str)

        if output:
            Path(output).write_text(output_data)
            console.print(f"[green]Results written to {output}[/]")
        else:
            print(output_data)
    else:
        display_scan_result(result)

    # Send to portal if requested
    if portal:
        console.print()
        send_to_portal(
            result.to_dict(),
            secrets_result.to_dict() if secrets_result else None,
            deps_result.to_dict() if deps_result else None
        )


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def stats(output_json: bool, verbose: bool):
    """Show statistics about installed IDEs and extensions."""
    setup_logging(verbose)
    
    with console.status("[bold cyan]Scanning for IDEs...[/]"):
        scanner = IDEScanner()
        result = scanner.scan()
        stats_data = scanner.get_extension_stats(result)
    
    if output_json:
        print(json.dumps(stats_data, indent=2))
    else:
        display_stats(stats_data)


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def dangerous(verbose: bool):
    """List extensions with dangerous permissions."""
    setup_logging(verbose)
    
    with console.status("[bold cyan]Scanning for extensions with dangerous permissions...[/]"):
        scanner = IDEScanner()
        result = scanner.scan()
    
    table = Table(
        title="Extensions with Dangerous Permissions",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    
    table.add_column("IDE", style="cyan")
    table.add_column("Extension", style="yellow")
    table.add_column("Version")
    table.add_column("Dangerous Permissions", style="red")
    
    found_any = False
    for ide in result.ides:
        for ext in ide.extensions:
            dangerous_perms = [p for p in ext.permissions if p.is_dangerous]
            if dangerous_perms:
                found_any = True
                perm_text = ", ".join(p.name for p in dangerous_perms)
                table.add_row(
                    ide.name,
                    ext.name,
                    ext.version,
                    perm_text,
                )
    
    if found_any:
        console.print(table)
    else:
        console.print("[green]No extensions with dangerous permissions found.[/]")


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--output-sarif", is_flag=True, help="Output in SARIF v2.1.0 format")
@click.option("--portal", is_flag=True, help="Send results to the portal")
@click.option("--check-staged", is_flag=True, help="Only scan files currently staged in git")
@click.option("--exit-code", "use_exit_code", is_flag=True, help="Exit with code 1 if secrets found (for use in hooks)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def secrets(output_json: bool, output_sarif: bool, portal: bool, check_staged: bool, use_exit_code: bool, verbose: bool):
    """Scan for plaintext secrets (wallet keys, API keys) in configuration files.

    This command scans .env files and similar configuration files for
    exposed secrets like Ethereum private keys, mnemonics, and API credentials.

    IMPORTANT: This scanner does NOT extract or display actual secret values.
    It only reports the presence and location of potential secrets.
    """
    setup_logging(verbose)

    # Handle --check-staged mode
    if check_staged:
        _scan_staged_secrets(use_exit_code)
        return
    
    with console.status("[bold cyan]Scanning for plaintext secrets...[/]"):
        scanner = SecretsScanner()
        result = scanner.scan()
    
    # Also run IDE scan if sending to portal (portal expects full scan data)
    ide_result = None
    deps_result = None
    if portal:
        with console.status("[bold cyan]Scanning for IDEs...[/]"):
            ide_scanner = IDEScanner()
            ide_result = ide_scanner.scan()
        
        with console.status("[bold cyan]Scanning for packages...[/]"):
            dep_scanner = DependencyScanner()
            deps_result = dep_scanner.scan()
    
    if output_sarif:
        sarif_data = secrets_result_to_sarif(result.to_dict(), version=__version__)
        print(to_sarif_json(sarif_data))
    elif output_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.findings:
            console.print(f"\n[bold red]⚠ Found {len(result.findings)} plaintext secrets![/]\n")
            
            table = Table(
                title="Exposed Secrets",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold red",
            )
            
            table.add_column("Type", style="yellow")
            table.add_column("Variable", style="cyan")
            table.add_column("File", style="dim")
            table.add_column("Line", justify="right")
            table.add_column("Severity")
            
            for finding in result.findings:
                severity_style = {
                    'critical': '[bold red]CRITICAL[/]',
                    'high': '[red]HIGH[/]',
                    'medium': '[yellow]MEDIUM[/]',
                    'low': '[green]LOW[/]',
                }.get(finding.severity, finding.severity)
                
                table.add_row(
                    finding.secret_type.replace('_', ' ').title(),
                    finding.variable_name or 'N/A',
                    str(finding.file_path),
                    str(finding.line_number) if finding.line_number else '-',
                    severity_style,
                )
            
            console.print(table)
            
            # Show recommendations
            console.print("\n[bold]Recommendations:[/]")
            seen_types = set()
            for finding in result.findings:
                if finding.secret_type not in seen_types:
                    seen_types.add(finding.secret_type)
                    console.print(f"  [cyan]•[/] {finding.recommendation}")
        else:
            console.print("[green]✓ No plaintext secrets detected.[/]")
        
        console.print(f"\n[dim]Scanned {len(result.scanned_paths)} files[/]")
    
    # Send to portal if requested
    if portal:
        console.print()
        send_to_portal(
            ide_result.to_dict() if ide_result else {"ides": [], "total_ides": 0, "total_extensions": 0},
            result.to_dict(),
            deps_result.to_dict() if deps_result else None
        )


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--global-only", is_flag=True, help="Only scan globally installed packages")
@click.option("--portal", is_flag=True, help="Send results to the portal")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def packages(output_json: bool, global_only: bool, portal: bool, verbose: bool):
    """Scan for installed packages and dependencies.
    
    Detects packages from various package managers including:
    - Python (pip, pipenv, poetry)
    - Node.js (npm, yarn)
    - Go modules
    - Rust (cargo)
    - Ruby (bundler)
    - PHP (composer)
    - Homebrew (macOS)
    """
    setup_logging(verbose)
    
    with console.status("[bold cyan]Scanning for installed packages...[/]"):
        scanner = DependencyScanner(scan_global=True)
        result = scanner.scan()
    
    # Also run IDE and secrets scans if sending to portal
    ide_result = None
    secrets_result = None
    if portal:
        with console.status("[bold cyan]Scanning for IDEs...[/]"):
            ide_scanner = IDEScanner()
            ide_result = ide_scanner.scan()
        
        with console.status("[bold cyan]Scanning for secrets...[/]"):
            secrets_scanner = SecretsScanner()
            secrets_result = secrets_scanner.scan()
    
    if output_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        console.print(f"\n[bold cyan]Found {len(result.packages)} packages[/]\n")
        
        if result.package_managers_found:
            console.print(f"[dim]Package managers: {', '.join(result.package_managers_found)}[/]\n")
        
        # Group by package manager
        by_manager = {}
        for pkg in result.packages:
            if global_only and pkg.install_type != 'global':
                continue
            if pkg.package_manager not in by_manager:
                by_manager[pkg.package_manager] = []
            by_manager[pkg.package_manager].append(pkg)
        
        for manager, pkgs in sorted(by_manager.items()):
            table = Table(
                title=f"{manager.upper()} Packages ({len(pkgs)})",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            
            table.add_column("Package", style="yellow")
            table.add_column("Version")
            table.add_column("Type", style="dim")
            
            # Show first 25 packages per manager
            for pkg in pkgs[:25]:
                table.add_row(pkg.name, pkg.version, pkg.install_type)
            
            if len(pkgs) > 25:
                table.add_row(f"[dim]... and {len(pkgs) - 25} more[/]", "", "")
            
            console.print(table)
            console.print()
        
        console.print(f"[dim]Scanned {len(result.scanned_projects)} project directories[/]")
    
    # Send to portal if requested
    if portal:
        console.print()
        send_to_portal(
            ide_result.to_dict() if ide_result else {"ides": [], "total_ides": 0, "total_extensions": 0},
            secrets_result.to_dict() if secrets_result else None,
            result.to_dict()
        )


@cli.command()
@click.option("--customer-key", "-k", type=str, help="Customer key (UUID) for portal authentication")
@click.option("--portal-url", "-p", type=str, help="Portal URL (e.g., http://portal.example.com)")
@click.option("--interval", "-i", type=int, help="Check-in/scan interval in minutes (default: 60)")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--log-file", type=click.Path(), help="Log file path")
@click.option("--pid-file", type=click.Path(), default="/tmp/ideviewer.pid", help="PID file path")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def daemon(
    customer_key: Optional[str],
    portal_url: Optional[str],
    interval: Optional[int],
    output: Optional[str],
    log_file: Optional[str],
    pid_file: str,
    foreground: bool,
    verbose: bool,
):
    """Start the daemon for continuous monitoring.
    
    The daemon will check in with the portal at the specified interval
    and report IDE/extension information.
    
    Examples:
    
        # Run with 30-minute check-in interval
        ideviewer daemon --interval 30 --foreground
        
        # Use saved configuration
        ideviewer daemon --foreground
    """
    setup_logging(verbose, log_file, daemon_mode=not foreground)
    
    # Setup API client
    api_client = None
    scan_interval = interval  # May be None, will use config or default
    
    if customer_key and portal_url:
        # New configuration provided
        api_client = APIClient(portal_url, customer_key)
        
        # Validate the key
        console.print("[cyan]Validating customer key...[/]")
        try:
            result = api_client.validate_key()
            if result.get('valid'):
                console.print(f"[green]✓ Key validated: {result.get('key_name')}[/]")
                console.print(f"[dim]  Hosts: {result.get('current_hosts')}/{result.get('max_hosts')}[/]")
                
                # Save configuration with interval
                save_interval = interval if interval else 60
                APIClient.save_config(portal_url, customer_key, save_interval)
                console.print(f"[dim]  Configuration saved (check-in interval: {save_interval} min)[/]")
                
                if scan_interval is None:
                    scan_interval = save_interval
            else:
                console.print(f"[red]✗ Key validation failed: {result.get('error')}[/]")
                sys.exit(1)
        except APIError as e:
            console.print(f"[red]✗ Failed to validate key: {e.message}[/]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]✗ Connection error: {e}[/]")
            sys.exit(1)
    
    elif customer_key or portal_url:
        # Only one provided - error
        console.print("[red]Both --customer-key and --portal-url are required together[/]")
        sys.exit(1)
    
    else:
        # Try to load from saved config
        config = APIClient.load_config()
        if config:
            api_client = APIClient(config.get('portal_url'), config.get('customer_key'))
            
            # Load saved interval if not overridden
            if scan_interval is None:
                scan_interval = config.get('scan_interval_minutes', 60)
            
            console.print(f"[dim]Using saved configuration (check-in interval: {scan_interval} min)[/]")
            
            # Validate the saved key still works
            try:
                result = api_client.validate_key()
                if not result.get('valid'):
                    console.print(f"[yellow]Warning: Saved key may be invalid[/]")
                    api_client = None
            except Exception:
                console.print("[yellow]Warning: Cannot reach portal, running in offline mode[/]")
                api_client = None
    
    # Default interval if still not set
    if scan_interval is None:
        scan_interval = 60
    
    if not foreground and sys.platform != "win32":
        console.print("[cyan]Starting daemon in background...[/]")
        daemonize()
    
    if not create_pid_file(pid_file):
        console.print("[red]Daemon is already running![/]")
        sys.exit(1)
    
    try:
        d = IDEViewerDaemon(
            output_path=output,
            scan_interval_minutes=scan_interval,
            api_client=api_client,
        )
        
        if foreground:
            console.print(f"[green]Daemon running (check-in interval: {scan_interval} minutes)[/]")
            if api_client:
                console.print(f"[dim]Reporting to: {api_client.portal_url}[/]")
            console.print("[dim]Press Ctrl+C to stop[/]")
        
        d.start()
        
    finally:
        remove_pid_file(pid_file)


@cli.command()
@click.option("--customer-key", "-k", type=str, required=True, help="Customer key (UUID)")
@click.option("--portal-url", "-p", type=str, required=True, help="Portal URL")
@click.option("--interval", "-i", type=int, default=60, help="Check-in interval in minutes (default: 60)")
def register(customer_key: str, portal_url: str, interval: int):
    """Register this machine with the portal and validate the customer key."""
    
    console.print(Panel(
        "[bold]IDE Viewer Registration[/]\n\n"
        f"Portal: {portal_url}\n"
        f"Key: {customer_key[:8]}...{customer_key[-4:]}\n"
        f"Check-in Interval: {interval} minutes",
        title="Registration",
        border_style="cyan"
    ))
    
    api_client = APIClient(portal_url, customer_key)
    
    # Step 1: Validate key
    console.print("\n[cyan]Step 1:[/] Validating customer key...")
    try:
        result = api_client.validate_key()
        if result.get('valid'):
            console.print(f"  [green]✓[/] Key is valid: [bold]{result.get('key_name')}[/]")
            console.print(f"  [dim]Hosts: {result.get('current_hosts')}/{result.get('max_hosts')}[/]")
        else:
            console.print(f"  [red]✗[/] Invalid key: {result.get('error')}")
            sys.exit(1)
    except APIError as e:
        console.print(f"  [red]✗[/] Validation failed: {e.message}")
        sys.exit(1)
    except Exception as e:
        console.print(f"  [red]✗[/] Connection error: {e}")
        sys.exit(1)
    
    # Step 2: Register host
    console.print("\n[cyan]Step 2:[/] Registering this machine...")
    try:
        result = api_client.register_host()
        if result.get('success'):
            console.print(f"  [green]✓[/] {result.get('message')}")
        else:
            console.print(f"  [red]✗[/] Registration failed: {result.get('error')}")
            sys.exit(1)
    except APIError as e:
        console.print(f"  [red]✗[/] Registration failed: {e.message}")
        sys.exit(1)
    
    # Step 3: Save configuration
    console.print("\n[cyan]Step 3:[/] Saving configuration...")
    try:
        APIClient.save_config(portal_url, customer_key, interval)
        config_path = APIClient.get_config_path()
        console.print(f"  [green]✓[/] Configuration saved to {config_path}")
        console.print(f"  [dim]Check-in interval: {interval} minutes[/]")
    except Exception as e:
        console.print(f"  [yellow]![/] Could not save config: {e}")
    
    # Step 4: Run initial scan
    console.print("\n[cyan]Step 4:[/] Running initial scan...")
    try:
        scanner = IDEScanner()
        scan_result = scanner.scan()
        
        response = api_client.submit_report(scan_result.to_dict())
        if response.get('success'):
            stats = response.get('stats', {})
            console.print(f"  [green]✓[/] Scan submitted successfully")
            console.print(f"  [dim]IDEs: {stats.get('total_ides', 0)}, Extensions: {stats.get('total_extensions', 0)}, Dangerous: {stats.get('dangerous_extensions', 0)}[/]")
        else:
            console.print(f"  [yellow]![/] Scan completed but failed to submit")
    except Exception as e:
        console.print(f"  [yellow]![/] Initial scan failed: {e}")
    
    # Step 5: Install gitleaks + global hooks
    console.print("\n[cyan]Step 5:[/] Installing pre-commit hooks...")
    try:
        from .gitleaks import install_gitleaks, is_gitleaks_installed, get_gitleaks_version
        from .hooks import install_global_hook
    except ImportError:
        from ideviewer.gitleaks import install_gitleaks, is_gitleaks_installed, get_gitleaks_version
        from ideviewer.hooks import install_global_hook

    try:
        if install_gitleaks():
            version = get_gitleaks_version()
            console.print(f"  [green]✓[/] gitleaks installed (version: {version})")
        else:
            console.print(f"  [yellow]![/] Could not install gitleaks; built-in scanner will be used")
    except Exception as e:
        console.print(f"  [yellow]![/] gitleaks installation failed: {e}")

    try:
        if install_global_hook():
            console.print(f"  [green]✓[/] Global pre-commit hooks installed")
        else:
            console.print(f"  [yellow]![/] Could not install global hooks")
    except Exception as e:
        console.print(f"  [yellow]![/] Hook installation failed: {e}")

    # Step 6: Start the daemon
    console.print("\n[cyan]Step 6:[/] Starting daemon...")
    daemon_started = _start_daemon_service()

    console.print("\n" + "="*50)
    console.print("[bold green]Registration complete![/]")
    if daemon_started:
        console.print("\nDaemon is running in the background.")
        console.print(f"[dim]Logs: {_get_default_log_dir() / 'daemon.log'}[/]")
    else:
        console.print("\nTo start the daemon manually:")
        console.print(f"  [cyan]ideviewer daemon --foreground[/]")


def _start_daemon_service() -> bool:
    """Start the daemon as a background service. Returns True if started."""
    import subprocess

    if sys.platform == 'darwin':
        plist = '/Library/LaunchDaemons/com.ideviewer.daemon.plist'
        if Path(plist).exists():
            try:
                # Unload first in case it's already loaded
                subprocess.run(
                    ['sudo', 'launchctl', 'unload', plist],
                    capture_output=True, timeout=10
                )
                result = subprocess.run(
                    ['sudo', 'launchctl', 'load', plist],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    console.print("  [green]✓[/] Daemon started via launchd")
                    return True
                else:
                    console.print(f"  [yellow]![/] launchctl load failed: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                console.print("  [yellow]![/] Timed out starting daemon")
            except Exception as e:
                console.print(f"  [yellow]![/] Could not start daemon: {e}")
        else:
            # Not installed via .pkg — start as a background process
            try:
                subprocess.Popen(
                    ['ideviewer', 'daemon'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                console.print("  [green]✓[/] Daemon started as background process")
                return True
            except Exception as e:
                console.print(f"  [yellow]![/] Could not start daemon: {e}")

    elif sys.platform == 'linux':
        service_file = Path('/lib/systemd/system/ideviewer.service')
        if service_file.exists():
            try:
                subprocess.run(['sudo', 'systemctl', 'daemon-reload'], capture_output=True, timeout=10)
                subprocess.run(['sudo', 'systemctl', 'enable', 'ideviewer'], capture_output=True, timeout=10)
                result = subprocess.run(
                    ['sudo', 'systemctl', 'start', 'ideviewer'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    console.print("  [green]✓[/] Daemon started via systemd")
                    return True
                else:
                    console.print(f"  [yellow]![/] systemctl start failed: {result.stderr.strip()}")
            except Exception as e:
                console.print(f"  [yellow]![/] Could not start daemon: {e}")
        else:
            try:
                subprocess.Popen(
                    ['ideviewer', 'daemon'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                console.print("  [green]✓[/] Daemon started as background process")
                return True
            except Exception as e:
                console.print(f"  [yellow]![/] Could not start daemon: {e}")

    elif sys.platform == 'win32':
        try:
            subprocess.Popen(
                ['ideviewer', 'daemon'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            )
            console.print("  [green]✓[/] Daemon started as background process")
            return True
        except Exception as e:
            console.print(f"  [yellow]![/] Could not start daemon: {e}")

    return False


@cli.command()
@click.option("--pid-file", type=click.Path(), default="/tmp/ideviewer.pid", help="PID file path")
def stop(pid_file: str):
    """Stop the running daemon."""
    import os
    import signal
    
    pid_path = Path(pid_file)
    
    if not pid_path.exists():
        console.print("[yellow]No daemon is running (PID file not found)[/]")
        return
    
    try:
        with open(pid_path, "r") as f:
            pid = int(f.read().strip())
        
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Sent stop signal to daemon (PID: {pid})[/]")
        
        # Remove PID file
        pid_path.unlink()
        
    except (ValueError, IOError) as e:
        console.print(f"[red]Error reading PID file: {e}[/]")
    except ProcessLookupError:
        console.print("[yellow]Daemon process not found (already stopped?)[/]")
        pid_path.unlink()
    except PermissionError:
        console.print("[red]Permission denied. Try running with sudo.[/]")


@cli.group()
def hooks():
    """Manage pre-commit hooks for secret scanning."""
    pass


@hooks.command()
def status():
    """Show the current status of global pre-commit hooks."""
    try:
        from .hooks import get_hook_status
    except ImportError:
        from ideviewer.hooks import get_hook_status

    hook_status = get_hook_status()

    console.print(Panel(
        "[bold]Pre-commit Hook Status[/]",
        border_style="cyan"
    ))

    installed = hook_status["installed"]
    if installed:
        console.print(f"  [green]Installed:[/]  Yes")
    else:
        console.print(f"  [red]Installed:[/]  No")

    console.print(f"  [cyan]Hook path:[/]  {hook_status['hook_path']}")
    console.print(f"  [cyan]Scanner:[/]    {hook_status['scanner']}")

    if hook_status["gitleaks_version"]:
        console.print(f"  [cyan]Gitleaks:[/]   {hook_status['gitleaks_version']}")
    else:
        console.print(f"  [dim]Gitleaks:[/]   Not installed (using built-in scanner)")


@hooks.command()
def install():
    """Install global pre-commit hooks."""
    try:
        from .gitleaks import install_gitleaks, get_gitleaks_version
        from .hooks import install_global_hook
    except ImportError:
        from ideviewer.gitleaks import install_gitleaks, get_gitleaks_version
        from ideviewer.hooks import install_global_hook

    console.print("[cyan]Installing gitleaks...[/]")
    if install_gitleaks():
        version = get_gitleaks_version()
        console.print(f"  [green]✓[/] gitleaks installed (version: {version})")
    else:
        console.print(f"  [yellow]![/] Could not install gitleaks; built-in scanner will be used")

    console.print("[cyan]Installing global hooks...[/]")
    if install_global_hook():
        console.print(f"  [green]✓[/] Global pre-commit hooks installed")
    else:
        console.print(f"  [red]✗[/] Failed to install global hooks")


@hooks.command()
def uninstall():
    """Uninstall global pre-commit hooks."""
    try:
        from .hooks import uninstall_global_hook
    except ImportError:
        from ideviewer.hooks import uninstall_global_hook

    if uninstall_global_hook():
        console.print("[green]✓ Global hooks uninstalled[/]")
    else:
        console.print("[red]✗ Failed to uninstall global hooks[/]")


def display_scan_result(result: ScanResult):
    """Display scan results in a rich format."""
    console.print()
    console.print(
        Panel(
            f"[bold]IDE Viewer Scan Results[/]\n"
            f"[dim]Platform: {result.platform}[/]\n"
            f"[dim]Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/]",
            box=box.DOUBLE,
        )
    )
    
    if not result.ides:
        console.print("[yellow]No IDEs detected.[/]")
        return
    
    for ide in result.ides:
        # Create IDE header
        status = "[green]●[/]" if ide.is_running else "[dim]○[/]"
        version_text = f" v{ide.version}" if ide.version else ""
        
        tree = Tree(
            f"{status} [bold cyan]{ide.name}[/]{version_text} "
            f"[dim]({len(ide.extensions)} extensions)[/]"
        )
        
        # Add paths
        if ide.install_path:
            tree.add(f"[dim]Install:[/] {ide.install_path}")
        if ide.extensions_path:
            tree.add(f"[dim]Extensions:[/] {ide.extensions_path}")
        
        # Add extensions
        if ide.extensions:
            ext_branch = tree.add("[bold]Extensions[/]")
            
            for ext in sorted(ide.extensions, key=lambda x: x.name.lower()):
                # Extension name with version
                ext_text = f"[yellow]{ext.name}[/] [dim]v{ext.version}[/]"
                
                # Add publisher if available
                if ext.publisher:
                    ext_text += f" [dim]by {ext.publisher}[/]"
                
                ext_node = ext_branch.add(ext_text)
                
                # Add dangerous permissions warning
                dangerous_perms = [p for p in ext.permissions if p.is_dangerous]
                if dangerous_perms:
                    perm_text = ", ".join(p.name for p in dangerous_perms)
                    ext_node.add(f"[red]⚠ Dangerous: {perm_text}[/]")
        
        console.print(tree)
        console.print()
    
    # Show errors if any
    if result.errors:
        console.print("[red]Errors during scan:[/]")
        for error in result.errors:
            console.print(f"  [red]• {error}[/]")


def display_stats(stats: dict):
    """Display statistics in a rich format."""
    console.print()
    
    # Summary panel
    summary = Table(box=box.SIMPLE, show_header=False)
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="yellow")
    
    summary.add_row("Total IDEs", str(stats["total_ides"]))
    summary.add_row("Total Extensions", str(stats["total_extensions"]))
    summary.add_row(
        "Extensions with Dangerous Permissions",
        f"[red]{stats['extensions_with_dangerous_permissions']}[/]"
    )
    
    console.print(Panel(summary, title="Summary", box=box.ROUNDED))
    
    # Extensions by IDE
    if stats["extensions_by_ide"]:
        ide_table = Table(
            title="Extensions by IDE",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
        )
        ide_table.add_column("IDE", style="cyan")
        ide_table.add_column("Extensions", justify="right", style="yellow")
        
        for ide_name, count in sorted(
            stats["extensions_by_ide"].items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            ide_table.add_row(ide_name, str(count))
        
        console.print(ide_table)
    
    # Permission counts
    if stats["permission_counts"]:
        perm_table = Table(
            title="Permission Usage",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
        )
        perm_table.add_column("Permission", style="cyan")
        perm_table.add_column("Count", justify="right")
        perm_table.add_column("Risk")
        
        for perm_name, data in sorted(
            stats["permission_counts"].items(),
            key=lambda x: x[1]["count"],
            reverse=True,
        )[:15]:  # Top 15
            risk = "[red]Dangerous[/]" if data["is_dangerous"] else "[green]Normal[/]"
            perm_table.add_row(perm_name, str(data["count"]), risk)
        
        console.print(perm_table)


@cli.command()
@click.option("--check", is_flag=True, help="Only check for updates, don't install")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def update(check: bool, yes: bool):
    """Check for and install updates from GitHub releases."""
    import tempfile
    from .updater import check_for_update, find_asset, download_asset, install_update

    console.print("[cyan]Checking for updates...[/]")

    try:
        has_update, current, latest, release = check_for_update()
    except Exception as e:
        console.print(f"[red]Failed to check for updates: {e}[/]")
        sys.exit(1)

    if not has_update:
        console.print(f"[green]You're up to date![/] (v{current})")
        return

    console.print(f"[yellow]Update available:[/] v{current} -> [bold]v{latest}[/]")

    # Show release notes
    body = release.get("body", "").strip()
    if body:
        console.print(f"\n[dim]Release notes:[/]")
        # Show first 10 lines
        for line in body.split("\n")[:10]:
            console.print(f"  [dim]{line}[/]")
        if len(body.split("\n")) > 10:
            console.print(f"  [dim]...[/]")
        console.print()

    if check:
        console.print(f"[dim]Run 'ideviewer update' to install.[/]")
        return

    # Find the right asset for this platform
    try:
        asset = find_asset(release)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(1)

    console.print(f"[dim]Package: {asset['name']} ({asset.get('size', 0) / 1024 / 1024:.1f} MB)[/]")

    if not yes:
        if not click.confirm("Install this update?"):
            console.print("[yellow]Update cancelled.[/]")
            return

    # Download and install
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            with console.status("[bold cyan]Downloading update...[/]"):
                file_path = download_asset(asset, tmp_dir)
            console.print(f"[green]Downloaded {asset['name']}[/]")

            console.print("[cyan]Installing update (may require sudo)...[/]")
            install_update(file_path)
            console.print(f"[bold green]Updated to v{latest}![/]")
            console.print("[dim]Restart the daemon to use the new version: ideviewer daemon --foreground[/]")

        except RuntimeError as e:
            console.print(f"[red]Update failed: {e}[/]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/]")
            sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
