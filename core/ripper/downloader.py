import aiohttp
import logging
from typing import Optional
from core.config import Config

logger = logging.getLogger("BugBot.Ripper.Downloader")

class JSDownloader:
    """Motor atómico para descarga segura de archivos JS a memoria."""
    
    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_size = 5 * 1024 * 1024 # 5MB limit

    async def download_to_ram(self, session: aiohttp.ClientSession, js_url: str) -> Optional[str]:
        """Descarga el código minificado a la RAM."""
        try:
            headers = {"User-Agent": Config.get_random_user_agent()}
            headers.update(Config.CUSTOM_HEADERS)

            async with session.get(js_url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    cl = response.headers.get("Content-Length")
                    if cl and int(cl) > self.max_size:
                        return None
                    
                    content = await response.text(errors='ignore')
                    if len(content) > self.max_size:
                        return None
                    
                    return content
        except Exception as e:
            logger.debug(f"[-] Error descargando JS {js_url}: {e}")
        return None
