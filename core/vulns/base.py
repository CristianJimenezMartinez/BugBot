import aiohttp
import asyncio
import logging
from typing import Optional, Dict
from core.config import Config

logger = logging.getLogger("BugBot.Vulns.Base")

class VulnScannerBase:
    """Clase base atómica para escáneres de vulnerabilidades."""
    
    def __init__(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, timeout: int = 10):
        self.session = session
        self.semaphore = semaphore
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _safe_get(self, url: str) -> Optional[Dict]:
        """Wrapper seguro con jitter adaptativo y manejo de errores."""
        await asyncio.sleep(Config.get_jitter())
        async with self.semaphore:
            try:
                headers = {"User-Agent": Config.get_random_user_agent()}
                headers.update(Config.CUSTOM_HEADERS)
                async with self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True) as response:
                    Config.register_rate_event(response.status)
                    content = await response.text(errors='ignore')
                    return {
                        "status": response.status,
                        "content": content,
                        "headers": response.headers,
                        "url": str(response.url)
                    }
            except Exception as e:
                return None
