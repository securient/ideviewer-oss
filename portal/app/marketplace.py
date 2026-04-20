"""
Marketplace API clients for fetching extension details.

Supports:
- VS Code Marketplace
- Open VSX (VSCodium)
- JetBrains Marketplace
"""

import json
import re
import ssl
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

_ssl_context = None  # Use system default SSL verification


class MarketplaceClient:
    """Base class for marketplace API clients."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def _make_request(self, url: str, method: str = 'GET', 
                      data: Optional[bytes] = None,
                      headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make an HTTP request."""
        req_headers = {
            'User-Agent': 'IDEViewer/1.0',
            'Accept': 'application/json',
        }
        if headers:
            req_headers.update(headers)
        
        request = Request(url, data=data, headers=req_headers, method=method)
        
        try:
            with urlopen(request, timeout=self.timeout, context=_ssl_context) as response:
                return json.loads(response.read().decode('utf-8'))
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            logger.error(f"Marketplace request failed: {e}")
            return {}


class VSCodeMarketplace(MarketplaceClient):
    """VS Code Marketplace API client."""
    
    BASE_URL = "https://marketplace.visualstudio.com"
    API_URL = f"{BASE_URL}/_apis/public/gallery"
    
    def get_extension(self, publisher: str, extension_name: str) -> Optional[Dict[str, Any]]:
        """
        Get extension details from VS Code Marketplace.
        
        Args:
            publisher: Extension publisher (e.g., 'ms-python')
            extension_name: Extension name (e.g., 'python')
        
        Returns:
            Extension details or None if not found.
        """
        url = f"{self.API_URL}/extensionquery"
        
        # VS Code Marketplace uses a POST query
        query = {
            "filters": [{
                "criteria": [
                    {"filterType": 7, "value": f"{publisher}.{extension_name}"}
                ],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 0,
                "sortOrder": 0
            }],
            "assetTypes": [],
            "flags": 950  # Include statistics, versions, etc.
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json;api-version=7.1-preview.1',
        }
        
        result = self._make_request(
            url, 
            method='POST', 
            data=json.dumps(query).encode('utf-8'),
            headers=headers
        )
        
        if not result:
            return None
        
        try:
            extensions = result.get('results', [{}])[0].get('extensions', [])
            if not extensions:
                return None
            
            ext = extensions[0]
            return self._parse_extension(ext, publisher, extension_name)
        except (IndexError, KeyError) as e:
            logger.error(f"Failed to parse VS Code extension: {e}")
            return None
    
    def _parse_extension(self, ext: Dict, publisher: str, name: str) -> Dict[str, Any]:
        """Parse VS Code Marketplace extension response."""
        # Extract statistics
        stats = {}
        for stat in ext.get('statistics', []):
            stat_name = stat.get('statisticName', '')
            stat_value = stat.get('value', 0)
            if stat_name == 'install':
                stats['installs'] = int(stat_value)
            elif stat_name == 'averagerating':
                stats['rating'] = round(stat_value, 2)
            elif stat_name == 'ratingcount':
                stats['rating_count'] = int(stat_value)
            elif stat_name == 'downloadCount':
                stats['downloads'] = int(stat_value)
        
        # Extract versions
        versions = []
        for ver in ext.get('versions', [])[:10]:  # Last 10 versions
            versions.append({
                'version': ver.get('version'),
                'last_updated': ver.get('lastUpdated'),
                'target_platform': ver.get('targetPlatform'),
            })
        
        # Extract properties
        properties = {}
        latest_version = ext.get('versions', [{}])[0] if ext.get('versions') else {}
        for prop in latest_version.get('properties', []):
            key = prop.get('key', '')
            value = prop.get('value', '')
            if key == 'Microsoft.VisualStudio.Services.Links.Source':
                properties['repository'] = value
            elif key == 'Microsoft.VisualStudio.Services.Links.GitHub':
                properties['github'] = value
            elif key == 'Microsoft.VisualStudio.Services.Links.Learn':
                properties['documentation'] = value
            elif key == 'Microsoft.VisualStudio.Code.Engine':
                properties['engine'] = value
        
        # Try to get GitHub from repository
        github_url = properties.get('github') or properties.get('repository', '')
        if 'github.com' not in github_url:
            github_url = None
        
        return {
            'id': f"{publisher}.{name}",
            'name': ext.get('displayName', name),
            'publisher': ext.get('publisher', {}).get('displayName', publisher),
            'publisher_id': publisher,
            'description': ext.get('shortDescription', ''),
            'long_description': ext.get('longDescription', ''),
            'version': ext.get('versions', [{}])[0].get('version', 'unknown'),
            'last_updated': ext.get('lastUpdated'),
            'release_date': ext.get('releaseDate'),
            'icon_url': self._get_asset_url(ext, 'Microsoft.VisualStudio.Services.Icons.Default'),
            'marketplace_url': f"{self.BASE_URL}/items?itemName={publisher}.{name}",
            'github_url': github_url,
            'repository_url': properties.get('repository'),
            'documentation_url': properties.get('documentation'),
            'categories': ext.get('categories', []),
            'tags': ext.get('tags', []),
            'installs': stats.get('installs', 0),
            'downloads': stats.get('downloads', stats.get('installs', 0)),
            'rating': stats.get('rating', 0),
            'rating_count': stats.get('rating_count', 0),
            'versions': versions,
            'engine': properties.get('engine'),
            'marketplace': 'vscode',
        }
    
    def _get_asset_url(self, ext: Dict, asset_type: str) -> Optional[str]:
        """Get asset URL from extension."""
        versions = ext.get('versions', [])
        if not versions:
            return None
        
        for asset in versions[0].get('files', []):
            if asset.get('assetType') == asset_type:
                return asset.get('source')
        return None


class OpenVSXMarketplace(MarketplaceClient):
    """Open VSX Registry API client (for VSCodium)."""
    
    BASE_URL = "https://open-vsx.org"
    API_URL = f"{BASE_URL}/api"
    
    def get_extension(self, publisher: str, extension_name: str) -> Optional[Dict[str, Any]]:
        """Get extension details from Open VSX."""
        url = f"{self.API_URL}/{quote(publisher)}/{quote(extension_name)}"
        
        result = self._make_request(url)
        
        if not result or 'error' in result:
            return None
        
        return self._parse_extension(result, publisher, extension_name)
    
    def _parse_extension(self, ext: Dict, publisher: str, name: str) -> Dict[str, Any]:
        """Parse Open VSX extension response."""
        return {
            'id': f"{publisher}.{name}",
            'name': ext.get('displayName', name),
            'publisher': ext.get('publishedBy', {}).get('loginName', publisher),
            'publisher_id': publisher,
            'description': ext.get('description', ''),
            'version': ext.get('version', 'unknown'),
            'last_updated': ext.get('timestamp'),
            'icon_url': ext.get('files', {}).get('icon'),
            'marketplace_url': f"{self.BASE_URL}/extension/{publisher}/{name}",
            'github_url': ext.get('repository'),
            'repository_url': ext.get('repository'),
            'homepage_url': ext.get('homepage'),
            'categories': ext.get('categories', []),
            'tags': ext.get('keywords', []),
            'downloads': ext.get('downloadCount', 0),
            'installs': ext.get('downloadCount', 0),
            'rating': ext.get('averageRating', 0),
            'rating_count': ext.get('reviewCount', 0),
            'versions': [],  # Would need separate call for version history
            'engine': ext.get('engines', {}).get('vscode'),
            'marketplace': 'openvsx',
        }


class JetBrainsMarketplace(MarketplaceClient):
    """JetBrains Marketplace API client."""
    
    BASE_URL = "https://plugins.jetbrains.com"
    API_URL = f"{BASE_URL}/api"
    
    def get_extension(self, plugin_id: str, plugin_name: str = None) -> Optional[Dict[str, Any]]:
        """
        Get plugin details from JetBrains Marketplace.
        
        Args:
            plugin_id: Plugin ID or XML ID
            plugin_name: Plugin name (optional, for search fallback)
        """
        # Try by ID first
        url = f"{self.API_URL}/plugins/{quote(plugin_id)}"
        result = self._make_request(url)
        
        if not result or 'error' in result:
            # Try search by name
            if plugin_name:
                return self._search_plugin(plugin_name)
            return None
        
        return self._parse_plugin(result)
    
    def _search_plugin(self, query: str) -> Optional[Dict[str, Any]]:
        """Search for a plugin by name."""
        url = f"{self.API_URL}/searchPlugins?search={quote(query)}&max=1"
        result = self._make_request(url)
        
        if not result or not result.get('plugins'):
            return None
        
        plugin_id = result['plugins'][0].get('id')
        if plugin_id:
            return self.get_extension(str(plugin_id))
        return None
    
    def _parse_plugin(self, plugin: Dict) -> Dict[str, Any]:
        """Parse JetBrains plugin response."""
        vendor = plugin.get('vendor', {})
        
        return {
            'id': str(plugin.get('id', '')),
            'name': plugin.get('name', ''),
            'publisher': vendor.get('name', 'Unknown'),
            'publisher_id': vendor.get('link', ''),
            'description': plugin.get('preview', ''),
            'long_description': plugin.get('description', ''),
            'version': plugin.get('version', 'unknown'),
            'icon_url': plugin.get('icon'),
            'marketplace_url': f"{self.BASE_URL}/plugin/{plugin.get('id')}",
            'github_url': self._extract_github(plugin),
            'repository_url': plugin.get('sourceCodeUrl'),
            'homepage_url': plugin.get('projectUrl'),
            'categories': plugin.get('tags', []),
            'tags': plugin.get('tags', []),
            'downloads': plugin.get('downloads', 0),
            'installs': plugin.get('downloads', 0),
            'rating': plugin.get('rating', 0),
            'rating_count': plugin.get('ratingsCount', 0),
            'versions': [],  # Would need separate call
            'marketplace': 'jetbrains',
        }
    
    def _extract_github(self, plugin: Dict) -> Optional[str]:
        """Extract GitHub URL from plugin data."""
        source_url = plugin.get('sourceCodeUrl', '')
        if 'github.com' in source_url:
            return source_url
        
        project_url = plugin.get('projectUrl', '')
        if 'github.com' in project_url:
            return project_url
        
        return None


def get_marketplace_client(marketplace: str) -> Optional[MarketplaceClient]:
    """Get the appropriate marketplace client."""
    clients = {
        'vscode': VSCodeMarketplace,
        'cursor': VSCodeMarketplace,  # Cursor uses VS Code marketplace
        'kiro': OpenVSXMarketplace,  # Kiro uses Open VSX (based on Code OSS)
        'vscodium': OpenVSXMarketplace,
        'openvsx': OpenVSXMarketplace,
        'jetbrains': JetBrainsMarketplace,
        'intellij-idea': JetBrainsMarketplace,
        'pycharm': JetBrainsMarketplace,
        'webstorm': JetBrainsMarketplace,
        'goland': JetBrainsMarketplace,
    }
    
    return clients.get(marketplace.lower(), VSCodeMarketplace)()


def fetch_extension_details(extension_id: str, marketplace: str = 'vscode') -> Optional[Dict[str, Any]]:
    """
    Fetch extension details from the appropriate marketplace.
    
    Args:
        extension_id: Extension identifier (e.g., 'ms-python.python')
        marketplace: Marketplace type ('vscode', 'jetbrains', etc.)
    
    Returns:
        Extension details dictionary or None if not found.
    """
    client = get_marketplace_client(marketplace)
    
    if marketplace.lower() in ('vscode', 'cursor', 'kiro', 'vscodium', 'openvsx'):
        # Parse publisher.extension format
        parts = extension_id.split('.', 1)
        if len(parts) != 2:
            return None
        publisher, name = parts
        return client.get_extension(publisher, name)
    
    elif marketplace.lower() in ('jetbrains', 'intellij-idea', 'pycharm', 'webstorm', 'goland'):
        return client.get_extension(extension_id)
    
    return None
