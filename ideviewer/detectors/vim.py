"""
Vim and Neovim detector.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

# Handle both direct execution and package import
try:
    from .base import BaseDetector
    from ..models import IDE, IDEType, Extension, Permission
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ideviewer.detectors.base import BaseDetector
    from ideviewer.models import IDE, IDEType, Extension, Permission


class VimDetector(BaseDetector):
    """Detector for Vim and Neovim."""
    
    def detect(self) -> List[IDE]:
        """Detect Vim and Neovim installations."""
        ides = []
        
        # Detect Vim
        vim = self._detect_vim()
        if vim:
            vim.extensions = self.parse_extensions(vim)
            ides.append(vim)
        
        # Detect Neovim
        neovim = self._detect_neovim()
        if neovim:
            neovim.extensions = self.parse_extensions(neovim)
            ides.append(neovim)
        
        return ides
    
    def _detect_vim(self) -> Optional[IDE]:
        """Detect Vim installation."""
        vim_path = self.find_executable("vim")
        if not vim_path:
            return None
        
        version = self.get_version(vim_path)
        
        # Find vim config and plugins
        vimrc = self.home / ".vimrc"
        vim_dir = self.home / ".vim"
        
        config_path = str(vimrc) if vimrc.exists() else None
        extensions_path = str(vim_dir) if vim_dir.exists() else None
        
        return IDE(
            ide_type=IDEType.VIM,
            name="Vim",
            version=version,
            install_path=vim_path,
            config_path=config_path,
            extensions_path=extensions_path,
            is_running=self.is_process_running(["vim", "gvim"]),
        )
    
    def _detect_neovim(self) -> Optional[IDE]:
        """Detect Neovim installation."""
        nvim_path = self.find_executable("nvim")
        if not nvim_path:
            return None
        
        version = self.get_version(nvim_path)
        
        # Find neovim config and plugins
        if self.is_windows:
            config_base = Path(os.environ.get("LOCALAPPDATA", "")) / "nvim"
            data_base = config_base
        else:
            config_base = self.home / ".config" / "nvim"
            data_base = self.home / ".local" / "share" / "nvim"
        
        config_path = str(config_base) if config_base.exists() else None
        
        # Check common plugin locations
        extensions_path = None
        plugin_paths = [
            data_base / "site" / "pack",  # Native package manager
            data_base / "plugged",  # vim-plug
            data_base / "lazy",  # lazy.nvim
            config_base / "pack",  # pack in config
        ]
        
        for pp in plugin_paths:
            if pp.exists():
                extensions_path = str(pp)
                break
        
        return IDE(
            ide_type=IDEType.NEOVIM,
            name="Neovim",
            version=version,
            install_path=nvim_path,
            config_path=config_path,
            extensions_path=extensions_path,
            is_running=self.is_process_running(["nvim", "neovim"]),
        )
    
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse Vim/Neovim plugins."""
        extensions = []
        
        if ide.ide_type == IDEType.VIM:
            extensions.extend(self._parse_vim_plugins(ide))
        else:
            extensions.extend(self._parse_neovim_plugins(ide))
        
        return extensions
    
    def _parse_vim_plugins(self, ide: IDE) -> List[Extension]:
        """Parse Vim plugins."""
        extensions = []
        
        vim_dir = self.home / ".vim"
        
        # Check bundle directory (Vundle, Pathogen)
        bundle_dir = vim_dir / "bundle"
        if bundle_dir.exists():
            for plugin_dir in bundle_dir.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                    ext = self._parse_vim_plugin(plugin_dir)
                    if ext:
                        extensions.append(ext)
        
        # Check pack directory (native package manager)
        pack_dir = vim_dir / "pack"
        if pack_dir.exists():
            extensions.extend(self._parse_pack_plugins(pack_dir))
        
        # Check plugged directory (vim-plug)
        plugged_dir = vim_dir / "plugged"
        if plugged_dir.exists():
            for plugin_dir in plugged_dir.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                    ext = self._parse_vim_plugin(plugin_dir)
                    if ext:
                        extensions.append(ext)
        
        return extensions
    
    def _parse_neovim_plugins(self, ide: IDE) -> List[Extension]:
        """Parse Neovim plugins."""
        extensions = []
        
        if not ide.extensions_path:
            return extensions
        
        ext_path = Path(ide.extensions_path)
        
        # Handle different plugin managers
        if "pack" in ext_path.name:
            extensions.extend(self._parse_pack_plugins(ext_path))
        elif "plugged" in ext_path.name:
            for plugin_dir in ext_path.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                    ext = self._parse_vim_plugin(plugin_dir)
                    if ext:
                        extensions.append(ext)
        elif "lazy" in ext_path.name:
            extensions.extend(self._parse_lazy_plugins(ext_path))
        
        return extensions
    
    def _parse_pack_plugins(self, pack_dir: Path) -> List[Extension]:
        """Parse plugins in Vim's native pack format."""
        extensions = []
        
        for namespace in pack_dir.iterdir():
            if not namespace.is_dir():
                continue
            
            for load_type in ["start", "opt"]:
                load_dir = namespace / load_type
                if not load_dir.exists():
                    continue
                
                for plugin_dir in load_dir.iterdir():
                    if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                        ext = self._parse_vim_plugin(plugin_dir)
                        if ext:
                            ext.enabled = (load_type == "start")
                            extensions.append(ext)
        
        return extensions
    
    def _parse_lazy_plugins(self, lazy_dir: Path) -> List[Extension]:
        """Parse lazy.nvim plugins."""
        extensions = []
        
        for plugin_dir in lazy_dir.iterdir():
            if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                ext = self._parse_vim_plugin(plugin_dir)
                if ext:
                    extensions.append(ext)
        
        return extensions
    
    def _parse_vim_plugin(self, plugin_dir: Path) -> Optional[Extension]:
        """Parse a Vim/Neovim plugin directory."""
        name = plugin_dir.name
        
        # Try to get info from README
        description = None
        readme_paths = ["README.md", "README", "README.txt", "readme.md"]
        for readme_name in readme_paths:
            readme = plugin_dir / readme_name
            if readme.exists():
                try:
                    with open(readme, "r", encoding="utf-8", errors="ignore") as f:
                        # Get first paragraph as description
                        content = f.read(500)
                        lines = content.split("\n")
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("="):
                                description = line[:200]
                                break
                except IOError:
                    pass
                break
        
        # Check for git info to get maintainer
        maintainer = None
        repository = None
        git_config = plugin_dir / ".git" / "config"
        if git_config.exists():
            try:
                with open(git_config, "r", encoding="utf-8") as f:
                    content = f.read()
                    match = re.search(r'url\s*=\s*(.+)', content)
                    if match:
                        repository = match.group(1).strip()
                        # Extract owner from GitHub URL
                        github_match = re.search(r'github\.com[:/]([^/]+)', repository)
                        if github_match:
                            maintainer = github_match.group(1)
            except IOError:
                pass
        
        # Get permissions based on plugin structure
        permissions = []
        
        if (plugin_dir / "autoload").exists():
            permissions.append(Permission(
                name="autoload",
                description="Has autoload functions",
                is_dangerous=False,
            ))
        
        if (plugin_dir / "plugin").exists():
            permissions.append(Permission(
                name="plugin",
                description="Runs on startup",
                is_dangerous=False,
            ))
        
        if (plugin_dir / "ftplugin").exists():
            permissions.append(Permission(
                name="ftplugin",
                description="Filetype-specific plugin",
                is_dangerous=False,
            ))
        
        # Check for potentially dangerous patterns
        lua_files = list(plugin_dir.rglob("*.lua"))
        vim_files = list(plugin_dir.rglob("*.vim"))
        
        for f in lua_files + vim_files:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read(2000)
                    if "system(" in content or "os.execute" in content or "jobstart" in content:
                        permissions.append(Permission(
                            name="shellExecution",
                            description="May execute shell commands",
                            is_dangerous=True,
                        ))
                        break
            except IOError:
                pass
        
        # Get last updated
        last_updated = None
        try:
            stat = plugin_dir.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            pass
        
        return Extension(
            id=name,
            name=name,
            version="unknown",
            maintainer=maintainer,
            description=description,
            repository=repository,
            install_path=str(plugin_dir),
            permissions=permissions,
            last_updated=last_updated,
        )
