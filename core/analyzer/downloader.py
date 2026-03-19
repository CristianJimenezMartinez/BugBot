import os
import aiohttp
import logging
from typing import Optional
from urllib.parse import urlparse
from core.config import Config
from core.analyzer.constants import EXT_CATEGORIES

logger = logging.getLogger("BugBot.Analyzer.Downloader")

class FileDownloader:
    """Motor atómicos para descarga segura y clasificada de archivos."""
    
    def __init__(self, downloads_dir: str, semaphore: aiohttp.TCPConnector, timeout: int = 30):
        self.downloads_dir = downloads_dir
        self.semaphore = semaphore
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._init_vault()

    def _init_vault(self):
        for cat in ['archives', 'databases', 'configs', 'crypto', 'logs', 'unpacked']:
            os.makedirs(os.path.join(self.downloads_dir, cat), exist_ok=True)

    def _get_category(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()
        for cat, exts in EXT_CATEGORIES.items():
            if ext in exts: return cat
        return 'unpacked'

    async def download(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        filename = os.path.basename(urlparse(url).path)
        if not filename: return None
        
        categoria = self._get_category(filename)
        safe_name = "".join([c for c in filename if c.isalnum() or c in ('.', '_', '-')]).strip()
        filepath = os.path.join(self.downloads_dir, categoria, safe_name)
        
        if os.path.exists(filepath): return filepath
            
        async with self.semaphore:
            try:
                headers = {"User-Agent": Config.get_random_user_agent()}
                headers.update(Config.CUSTOM_HEADERS)
                max_size = 50 * 1024 * 1024 
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        content_len = int(response.headers.get('Content-Length', 0))
                        if content_len > max_size: return None
                            
                        with open(filepath, 'wb') as f:
                            downloaded = 0
                            async for chunk in response.content.iter_chunked(8192):
                                downloaded += len(chunk)
                                if downloaded > max_size: break
                                f.write(chunk)
                        return filepath
            except Exception as e:
                logger.error(f"[-] Error bajando {url}: {e}")
        return None
