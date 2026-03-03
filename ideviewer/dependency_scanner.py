"""
Dependency Scanner - Detects installed packages across package managers.

Scans for dependencies from:
- Python (pip, pipenv, poetry)
- Node.js (npm, yarn, pnpm)
- Go (go modules)
- Rust (cargo)
- Ruby (bundler)
- PHP (composer)
"""

import os
import re
import json
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Package:
    """Represents an installed package."""
    name: str
    version: str
    package_manager: str  # pip, npm, go, cargo, gem, composer
    install_type: str = "project"  # global, project
    project_path: Optional[str] = None
    lifecycle_hooks: Optional[Dict[str, str]] = None  # npm lifecycle hooks (preinstall, postinstall, etc.)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "name": self.name,
            "version": self.version,
            "package_manager": self.package_manager,
            "install_type": self.install_type,
            "project_path": self.project_path,
        }
        if self.lifecycle_hooks:
            result["lifecycle_hooks"] = self.lifecycle_hooks
        return result


@dataclass
class DependencyResult:
    """Result of a dependency scan."""
    timestamp: datetime
    packages: List[Package] = field(default_factory=list)
    package_managers_found: List[str] = field(default_factory=list)
    scanned_projects: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        # Group packages by manager
        by_manager = {}
        for pkg in self.packages:
            if pkg.package_manager not in by_manager:
                by_manager[pkg.package_manager] = []
            by_manager[pkg.package_manager].append(pkg.to_dict())
        
        return {
            "timestamp": self.timestamp.isoformat(),
            "packages": [p.to_dict() for p in self.packages],
            "packages_by_manager": by_manager,
            "total_packages": len(self.packages),
            "package_managers_found": self.package_managers_found,
            "scanned_projects": self.scanned_projects,
            "summary": {
                manager: len(pkgs) for manager, pkgs in by_manager.items()
            },
            "errors": self.errors,
        }


class DependencyScanner:
    """
    Scanner for detecting installed packages across multiple package managers.
    """
    
    # Directories to search for projects
    SEARCH_DIRS = [
        '',  # Home directory
        'Documents',
        'Projects',
        'Development',
        'dev',
        'projects',
        'code',
        'src',
        'work',
        'workspace',
        'repos',
        'git',
        'github',
        'go/src',  # Go workspace
    ]
    
    # Skip these directories
    SKIP_DIRS = {
        'node_modules', 'venv', '.venv', '__pycache__', '.git',
        'vendor', 'dist', 'build', '.cache', 'target', '.cargo',
        'Library', 'Applications', '.Trash', 'tmp', 'temp',
    }
    
    def __init__(self, max_depth: int = 4, scan_global: bool = True):
        """
        Initialize the dependency scanner.
        
        Args:
            max_depth: Maximum directory depth for project scanning
            scan_global: Whether to scan globally installed packages
        """
        self.max_depth = max_depth
        self.scan_global = scan_global
        self.home_dir = Path.home()
    
    def scan(self, additional_paths: Optional[List[str]] = None) -> DependencyResult:
        """
        Scan for installed dependencies.
        
        Args:
            additional_paths: Additional project paths to scan
        
        Returns:
            DependencyResult with all found packages
        """
        result = DependencyResult(timestamp=datetime.now())
        seen_packages: Set[str] = set()  # Dedupe: "manager:name:version:path"
        
        # Scan global packages first
        if self.scan_global:
            self._scan_global_packages(result, seen_packages)
        
        # Build list of directories to scan for projects
        scan_dirs = []
        for subdir in self.SEARCH_DIRS:
            path = self.home_dir / subdir if subdir else self.home_dir
            if path.exists() and path.is_dir():
                scan_dirs.append(path)
        
        # Add additional paths
        if additional_paths:
            for p in additional_paths:
                path = Path(p)
                if path.exists():
                    scan_dirs.append(path)
        
        # Scan directories for projects
        for scan_dir in scan_dirs:
            try:
                self._scan_directory(scan_dir, result, seen_packages, depth=0)
            except Exception as e:
                error_msg = f"Error scanning {scan_dir}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)
        
        return result
    
    def _scan_global_packages(self, result: DependencyResult, seen: Set[str]):
        """Scan globally installed packages."""
        
        # Python global packages (pip)
        try:
            self._scan_pip_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning pip global: {e}")
            result.errors.append(f"pip scan: {str(e)}")
        
        # Node.js global packages (npm)
        try:
            self._scan_npm_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning npm global: {e}")
            result.errors.append(f"npm scan: {str(e)}")
        
        # Go packages
        try:
            self._scan_go_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning go global: {e}")
        
        # Ruby gems
        try:
            self._scan_gem_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning gem global: {e}")
        
        # Rust cargo
        try:
            self._scan_cargo_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning cargo global: {e}")
        
        # Homebrew (macOS)
        try:
            self._scan_brew_global(result, seen)
        except Exception as e:
            logger.debug(f"Error scanning brew global: {e}")
    
    def _scan_pip_global(self, result: DependencyResult, seen: Set[str]):
        """Scan globally installed pip packages."""
        packages_found = False
        
        # Try multiple pip commands in order of preference
        pip_commands = [
            ['python3', '-m', 'pip', 'list', '--format=json'],
            ['python', '-m', 'pip', 'list', '--format=json'],
            ['pip3', 'list', '--format=json'],
            ['pip', 'list', '--format=json'],
        ]
        
        for cmd in pip_commands:
            try:
                output = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=60,
                    env={**os.environ, 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
                )
                if output.returncode == 0 and output.stdout.strip():
                    try:
                        packages = json.loads(output.stdout)
                        if packages:
                            packages_found = True
                            if "pip" not in result.package_managers_found:
                                result.package_managers_found.append("pip")
                            
                            for pkg in packages:
                                name = pkg.get('name', '')
                                version = pkg.get('version', 'unknown')
                                key = f"pip:{name}:{version}:global"
                                if key not in seen and name:
                                    seen.add(key)
                                    result.packages.append(Package(
                                        name=name,
                                        version=version,
                                        package_manager="pip",
                                        install_type="global",
                                    ))
                            break  # Success, stop trying other commands
                    except json.JSONDecodeError:
                        continue  # Try next command
            except FileNotFoundError:
                continue  # Try next command
            except subprocess.TimeoutExpired:
                logger.debug(f"pip command timed out: {cmd}")
                continue
            except Exception as e:
                logger.debug(f"pip command failed ({cmd}): {e}")
                continue
        
        if not packages_found:
            logger.debug("No pip packages found with any command")
    
    def _scan_npm_global(self, result: DependencyResult, seen: Set[str]):
        """Scan globally installed npm packages."""
        try:
            # Try npm list with JSON output
            output = subprocess.run(
                ['npm', 'list', '-g', '--json', '--depth=0'],
                capture_output=True, text=True, timeout=60
            )
            
            # npm may return non-zero but still have valid output
            if output.stdout.strip():
                try:
                    data = json.loads(output.stdout)
                    dependencies = data.get('dependencies', {})
                    
                    if dependencies:
                        if "npm" not in result.package_managers_found:
                            result.package_managers_found.append("npm")
                        
                        for name, info in dependencies.items():
                            if isinstance(info, dict):
                                version = info.get('version', 'unknown')
                            else:
                                version = 'unknown'
                            key = f"npm:{name}:{version}:global"
                            if key not in seen:
                                seen.add(key)
                                hooks = self._check_npm_global_lifecycle_hooks(name)
                                result.packages.append(Package(
                                    name=name,
                                    version=version,
                                    package_manager="npm",
                                    install_type="global",
                                    lifecycle_hooks=hooks,
                                ))
                except json.JSONDecodeError:
                    # Try parsing non-JSON output
                    self._scan_npm_global_fallback(result, seen)
        except FileNotFoundError:
            pass  # npm not installed
        except subprocess.TimeoutExpired:
            logger.debug("npm list timed out")
        except Exception as e:
            logger.debug(f"npm global scan error: {e}")
    
    # npm lifecycle hooks that are security-relevant
    NPM_LIFECYCLE_HOOKS = [
        'preinstall', 'install', 'postinstall',
        'preuninstall', 'uninstall', 'postuninstall',
        'prepare', 'prepublish', 'prepublishOnly',
    ]
    
    def _check_npm_lifecycle_hooks(self, package_name: str, 
                                     node_modules_path: Path) -> Optional[Dict[str, str]]:
        """Check if an npm package has lifecycle hooks in its package.json."""
        pkg_json_path = node_modules_path / package_name / 'package.json'
        
        # Handle scoped packages like @scope/name
        if not pkg_json_path.exists() and '/' in package_name:
            parts = package_name.split('/')
            pkg_json_path = node_modules_path / parts[0] / parts[1] / 'package.json'
        
        if not pkg_json_path.exists():
            return None
        
        try:
            with open(pkg_json_path, 'r') as f:
                data = json.load(f)
            
            scripts = data.get('scripts', {})
            hooks = {}
            for hook_name in self.NPM_LIFECYCLE_HOOKS:
                if hook_name in scripts:
                    hooks[hook_name] = scripts[hook_name]
            
            return hooks if hooks else None
        except Exception as e:
            logger.debug(f"Error reading {pkg_json_path}: {e}")
            return None
    
    def _check_npm_global_lifecycle_hooks(self, package_name: str) -> Optional[Dict[str, str]]:
        """Check lifecycle hooks for a globally installed npm package."""
        try:
            output = subprocess.run(
                ['npm', 'root', '-g'],
                capture_output=True, text=True, timeout=10
            )
            if output.returncode == 0 and output.stdout.strip():
                global_nm = Path(output.stdout.strip())
                return self._check_npm_lifecycle_hooks(package_name, global_nm)
        except Exception:
            pass
        return None
    
    def _scan_npm_global_fallback(self, result: DependencyResult, seen: Set[str]):
        """Fallback npm scan using non-JSON output."""
        try:
            output = subprocess.run(
                ['npm', 'list', '-g', '--depth=0'],
                capture_output=True, text=True, timeout=60
            )
            if output.stdout:
                if "npm" not in result.package_managers_found:
                    result.package_managers_found.append("npm")
                
                # Parse lines like: ├── package@version
                for line in output.stdout.split('\n'):
                    match = re.search(r'[├└]── ([^@]+)@(.+)$', line)
                    if match:
                        name, version = match.groups()
                        key = f"npm:{name}:{version}:global"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="npm",
                                install_type="global",
                            ))
        except Exception as e:
            logger.debug(f"npm fallback scan error: {e}")
    
    def _scan_go_global(self, result: DependencyResult, seen: Set[str]):
        """Scan Go installed packages/tools."""
        go_bin = self.home_dir / 'go' / 'bin'
        if not go_bin.exists():
            return
        
        if "go" not in result.package_managers_found:
            result.package_managers_found.append("go")
        
        # List Go binaries (installed tools)
        try:
            for item in go_bin.iterdir():
                if item.is_file() and os.access(item, os.X_OK):
                    key = f"go:{item.name}:installed:global"
                    if key not in seen:
                        seen.add(key)
                        result.packages.append(Package(
                            name=item.name,
                            version="installed",  # Can't easily get version from binary
                            package_manager="go",
                            install_type="global",
                        ))
        except Exception as e:
            logger.debug(f"Error scanning go bin: {e}")
    
    def _scan_gem_global(self, result: DependencyResult, seen: Set[str]):
        """Scan globally installed Ruby gems."""
        try:
            output = subprocess.run(
                ['gem', 'list', '--local'],
                capture_output=True, text=True, timeout=60
            )
            if output.returncode == 0 and output.stdout:
                if "gem" not in result.package_managers_found:
                    result.package_managers_found.append("gem")
                
                # Parse lines like: bundler (2.4.10, 2.3.26)
                for line in output.stdout.split('\n'):
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s+\((.+)\)$', line.strip())
                    if match:
                        name = match.group(1)
                        versions = match.group(2).split(', ')
                        version = versions[0] if versions else 'unknown'
                        
                        key = f"gem:{name}:{version}:global"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="gem",
                                install_type="global",
                            ))
        except FileNotFoundError:
            pass  # gem not installed
        except Exception as e:
            logger.debug(f"gem global scan error: {e}")
    
    def _scan_cargo_global(self, result: DependencyResult, seen: Set[str]):
        """Scan globally installed Rust cargo packages."""
        try:
            output = subprocess.run(
                ['cargo', 'install', '--list'],
                capture_output=True, text=True, timeout=60
            )
            if output.returncode == 0 and output.stdout:
                if "cargo" not in result.package_managers_found:
                    result.package_managers_found.append("cargo")
                
                # Parse lines like: ripgrep v14.0.3:
                current_pkg = None
                for line in output.stdout.split('\n'):
                    # Package line: name vX.X.X:
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s+v(.+):$', line.strip())
                    if match:
                        name, version = match.groups()
                        key = f"cargo:{name}:{version}:global"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="cargo",
                                install_type="global",
                            ))
        except FileNotFoundError:
            pass  # cargo not installed
        except Exception as e:
            logger.debug(f"cargo global scan error: {e}")
    
    def _scan_brew_global(self, result: DependencyResult, seen: Set[str]):
        """Scan Homebrew installed packages (macOS)."""
        try:
            # Get formulae (regular packages)
            output = subprocess.run(
                ['brew', 'list', '--formula', '--versions'],
                capture_output=True, text=True, timeout=120
            )
            if output.returncode == 0 and output.stdout:
                if "brew" not in result.package_managers_found:
                    result.package_managers_found.append("brew")
                
                # Parse lines like: git 2.43.0
                for line in output.stdout.split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]  # Take first version if multiple
                        
                        key = f"brew:{name}:{version}:global"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="brew",
                                install_type="global",
                            ))
            
            # Also get casks (GUI apps)
            output_casks = subprocess.run(
                ['brew', 'list', '--cask', '--versions'],
                capture_output=True, text=True, timeout=120
            )
            if output_casks.returncode == 0 and output_casks.stdout:
                for line in output_casks.stdout.split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        
                        key = f"brew-cask:{name}:{version}:global"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="brew-cask",
                                install_type="global",
                            ))
                            
                if "brew-cask" not in result.package_managers_found:
                    result.package_managers_found.append("brew-cask")
                    
        except FileNotFoundError:
            pass  # brew not installed
        except Exception as e:
            logger.debug(f"brew global scan error: {e}")
    
    def _scan_directory(self, directory: Path, result: DependencyResult, 
                        seen: Set[str], depth: int):
        """Recursively scan directories for project dependency files."""
        if depth > self.max_depth:
            return
        
        try:
            items = list(directory.iterdir())
        except PermissionError:
            return
        
        # Check for project files in this directory
        item_names = {item.name for item in items}
        
        # Python projects
        if 'requirements.txt' in item_names:
            self._parse_requirements_txt(directory / 'requirements.txt', result, seen)
        if 'Pipfile.lock' in item_names:
            self._parse_pipfile_lock(directory / 'Pipfile.lock', result, seen)
        if 'poetry.lock' in item_names:
            self._parse_poetry_lock(directory / 'poetry.lock', result, seen)
        if 'pyproject.toml' in item_names and 'poetry.lock' not in item_names:
            self._parse_pyproject_toml(directory / 'pyproject.toml', result, seen)
        
        # Node.js projects
        if 'package-lock.json' in item_names:
            self._parse_package_lock(directory / 'package-lock.json', result, seen)
        elif 'yarn.lock' in item_names:
            self._parse_yarn_lock(directory / 'yarn.lock', result, seen)
        elif 'package.json' in item_names:
            self._parse_package_json(directory / 'package.json', result, seen)
        
        # Go projects
        if 'go.mod' in item_names:
            self._parse_go_mod(directory / 'go.mod', result, seen)
        
        # Rust projects
        if 'Cargo.lock' in item_names:
            self._parse_cargo_lock(directory / 'Cargo.lock', result, seen)
        elif 'Cargo.toml' in item_names:
            self._parse_cargo_toml(directory / 'Cargo.toml', result, seen)
        
        # Ruby projects
        if 'Gemfile.lock' in item_names:
            self._parse_gemfile_lock(directory / 'Gemfile.lock', result, seen)
        
        # PHP projects
        if 'composer.lock' in item_names:
            self._parse_composer_lock(directory / 'composer.lock', result, seen)
        
        # Recurse into subdirectories
        for item in items:
            if item.is_dir() and item.name not in self.SKIP_DIRS:
                if not item.name.startswith('.'):
                    self._scan_directory(item, result, seen, depth + 1)
    
    def _parse_requirements_txt(self, file_path: Path, result: DependencyResult, 
                                 seen: Set[str]):
        """Parse Python requirements.txt."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "pip" not in result.package_managers_found:
                result.package_managers_found.append("pip")
            
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    
                    # Parse package==version, package>=version, etc.
                    match = re.match(r'^([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?', line)
                    if match:
                        name = match.group(1)
                        version = match.group(2) or 'any'
                        
                        key = f"pip:{name}:{version}:{file_path.parent}"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="pip",
                                install_type="project",
                                project_path=str(file_path.parent),
                            ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_pipfile_lock(self, file_path: Path, result: DependencyResult,
                            seen: Set[str]):
        """Parse Pipenv Pipfile.lock."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "pipenv" not in result.package_managers_found:
                result.package_managers_found.append("pipenv")
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for section in ['default', 'develop']:
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get('version', 'unknown').lstrip('=')
                    
                    key = f"pipenv:{name}:{version}:{file_path.parent}"
                    if key not in seen:
                        seen.add(key)
                        result.packages.append(Package(
                            name=name,
                            version=version,
                            package_manager="pipenv",
                            install_type="project",
                            project_path=str(file_path.parent),
                        ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_poetry_lock(self, file_path: Path, result: DependencyResult,
                           seen: Set[str]):
        """Parse Poetry poetry.lock (TOML format)."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "poetry" not in result.package_managers_found:
                result.package_managers_found.append("poetry")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Simple TOML parsing for [[package]] sections
            for match in re.finditer(
                r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"',
                content
            ):
                name, version = match.groups()
                
                key = f"poetry:{name}:{version}:{file_path.parent}"
                if key not in seen:
                    seen.add(key)
                    result.packages.append(Package(
                        name=name,
                        version=version,
                        package_manager="poetry",
                        install_type="project",
                        project_path=str(file_path.parent),
                    ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_pyproject_toml(self, file_path: Path, result: DependencyResult,
                              seen: Set[str]):
        """Parse pyproject.toml for dependencies."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check if it's a poetry or standard project
            if '[tool.poetry.dependencies]' in content:
                # Poetry project (handled by poetry.lock)
                return
            
            # Look for [project.dependencies]
            if '[project]' not in content:
                return
            
            result.scanned_projects.append(str(file_path.parent))
            if "pip" not in result.package_managers_found:
                result.package_managers_found.append("pip")
            
            # Extract dependencies array
            dep_match = re.search(
                r'dependencies\s*=\s*\[(.*?)\]',
                content, re.DOTALL
            )
            if dep_match:
                deps_str = dep_match.group(1)
                for match in re.finditer(r'"([^"]+)"', deps_str):
                    dep = match.group(1)
                    name_match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                    if name_match:
                        name = name_match.group(1)
                        version = dep[len(name):].strip() or 'any'
                        
                        key = f"pip:{name}:{version}:{file_path.parent}"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="pip",
                                install_type="project",
                                project_path=str(file_path.parent),
                            ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_package_json(self, file_path: Path, result: DependencyResult,
                            seen: Set[str]):
        """Parse npm package.json."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "npm" not in result.package_managers_found:
                result.package_managers_found.append("npm")
            
            node_modules = file_path.parent / 'node_modules'
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for section in ['dependencies', 'devDependencies']:
                deps = data.get(section, {})
                for name, version in deps.items():
                    key = f"npm:{name}:{version}:{file_path.parent}"
                    if key not in seen:
                        seen.add(key)
                        hooks = self._check_npm_lifecycle_hooks(name, node_modules) if node_modules.exists() else None
                        result.packages.append(Package(
                            name=name,
                            version=version,
                            package_manager="npm",
                            install_type="project",
                            project_path=str(file_path.parent),
                            lifecycle_hooks=hooks,
                        ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_package_lock(self, file_path: Path, result: DependencyResult,
                            seen: Set[str]):
        """Parse npm package-lock.json (v2/v3 format)."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "npm" not in result.package_managers_found:
                result.package_managers_found.append("npm")
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            node_modules = file_path.parent / 'node_modules'
            
            # package-lock v2/v3 format
            packages = data.get('packages', {})
            for pkg_path, info in packages.items():
                if not pkg_path or pkg_path == '':  # Skip root
                    continue
                
                # Extract package name from path
                name = pkg_path.split('node_modules/')[-1]
                if '/' in name and not name.startswith('@'):
                    continue  # Skip nested deps for brevity
                
                version = info.get('version', 'unknown')
                
                key = f"npm:{name}:{version}:{file_path.parent}"
                if key not in seen:
                    seen.add(key)
                    hooks = self._check_npm_lifecycle_hooks(name, node_modules) if node_modules.exists() else None
                    result.packages.append(Package(
                        name=name,
                        version=version,
                        package_manager="npm",
                        install_type="project",
                        project_path=str(file_path.parent),
                        lifecycle_hooks=hooks,
                    ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_yarn_lock(self, file_path: Path, result: DependencyResult,
                         seen: Set[str]):
        """Parse yarn.lock."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "yarn" not in result.package_managers_found:
                result.package_managers_found.append("yarn")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse yarn.lock format
            for match in re.finditer(
                r'^"?([^@\s]+)@[^:]+:\s*\n\s+version\s+"([^"]+)"',
                content, re.MULTILINE
            ):
                name, version = match.groups()
                
                key = f"yarn:{name}:{version}:{file_path.parent}"
                if key not in seen:
                    seen.add(key)
                    result.packages.append(Package(
                        name=name,
                        version=version,
                        package_manager="yarn",
                        install_type="project",
                        project_path=str(file_path.parent),
                    ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_go_mod(self, file_path: Path, result: DependencyResult,
                      seen: Set[str]):
        """Parse Go go.mod."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "go" not in result.package_managers_found:
                result.package_managers_found.append("go")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse require blocks
            in_require = False
            for line in content.split('\n'):
                line = line.strip()
                
                if line.startswith('require ('):
                    in_require = True
                    continue
                elif line == ')':
                    in_require = False
                    continue
                elif line.startswith('require '):
                    # Single require
                    parts = line[8:].split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        key = f"go:{name}:{version}:{file_path.parent}"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="go",
                                install_type="project",
                                project_path=str(file_path.parent),
                            ))
                elif in_require and line and not line.startswith('//'):
                    parts = line.split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        key = f"go:{name}:{version}:{file_path.parent}"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="go",
                                install_type="project",
                                project_path=str(file_path.parent),
                            ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_cargo_lock(self, file_path: Path, result: DependencyResult,
                          seen: Set[str]):
        """Parse Rust Cargo.lock."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "cargo" not in result.package_managers_found:
                result.package_managers_found.append("cargo")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse [[package]] sections
            for match in re.finditer(
                r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"',
                content
            ):
                name, version = match.groups()
                
                key = f"cargo:{name}:{version}:{file_path.parent}"
                if key not in seen:
                    seen.add(key)
                    result.packages.append(Package(
                        name=name,
                        version=version,
                        package_manager="cargo",
                        install_type="project",
                        project_path=str(file_path.parent),
                    ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_cargo_toml(self, file_path: Path, result: DependencyResult,
                          seen: Set[str]):
        """Parse Rust Cargo.toml."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "cargo" not in result.package_managers_found:
                result.package_managers_found.append("cargo")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Look for [dependencies] section
            in_deps = False
            for line in content.split('\n'):
                line = line.strip()
                
                if line == '[dependencies]' or line == '[dev-dependencies]':
                    in_deps = True
                    continue
                elif line.startswith('['):
                    in_deps = False
                    continue
                elif in_deps and '=' in line:
                    name = line.split('=')[0].strip()
                    version_part = line.split('=', 1)[1].strip()
                    
                    # Handle different version formats
                    if version_part.startswith('"'):
                        version = version_part.strip('"')
                    elif version_part.startswith('{'):
                        ver_match = re.search(r'version\s*=\s*"([^"]+)"', version_part)
                        version = ver_match.group(1) if ver_match else 'unknown'
                    else:
                        version = version_part
                    
                    key = f"cargo:{name}:{version}:{file_path.parent}"
                    if key not in seen:
                        seen.add(key)
                        result.packages.append(Package(
                            name=name,
                            version=version,
                            package_manager="cargo",
                            install_type="project",
                            project_path=str(file_path.parent),
                        ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_gemfile_lock(self, file_path: Path, result: DependencyResult,
                            seen: Set[str]):
        """Parse Ruby Gemfile.lock."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "gem" not in result.package_managers_found:
                result.package_managers_found.append("gem")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse specs section
            in_specs = False
            for line in content.split('\n'):
                if '  specs:' in line:
                    in_specs = True
                    continue
                elif in_specs and line and not line.startswith(' '):
                    in_specs = False
                    continue
                elif in_specs:
                    # Match gem entries like "    actioncable (7.0.0)"
                    match = re.match(r'^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)', line)
                    if match:
                        name, version = match.groups()
                        
                        key = f"gem:{name}:{version}:{file_path.parent}"
                        if key not in seen:
                            seen.add(key)
                            result.packages.append(Package(
                                name=name,
                                version=version,
                                package_manager="gem",
                                install_type="project",
                                project_path=str(file_path.parent),
                            ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    def _parse_composer_lock(self, file_path: Path, result: DependencyResult,
                             seen: Set[str]):
        """Parse PHP composer.lock."""
        try:
            result.scanned_projects.append(str(file_path.parent))
            if "composer" not in result.package_managers_found:
                result.package_managers_found.append("composer")
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for section in ['packages', 'packages-dev']:
                packages = data.get(section, [])
                for pkg in packages:
                    name = pkg.get('name', 'unknown')
                    version = pkg.get('version', 'unknown')
                    
                    key = f"composer:{name}:{version}:{file_path.parent}"
                    if key not in seen:
                        seen.add(key)
                        result.packages.append(Package(
                            name=name,
                            version=version,
                            package_manager="composer",
                            install_type="project",
                            project_path=str(file_path.parent),
                        ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")


def scan_dependencies(additional_paths: Optional[List[str]] = None,
                      scan_global: bool = True) -> DependencyResult:
    """
    Convenience function to scan for dependencies.
    
    Args:
        additional_paths: Additional paths to scan
        scan_global: Whether to scan globally installed packages
    
    Returns:
        DependencyResult with all found packages
    """
    scanner = DependencyScanner(scan_global=scan_global)
    return scanner.scan(additional_paths)
