import asyncio
import aiohttp
import logging
from typing import List, Set
from core.config import Config
from core.ripper.downloader import JSDownloader
from core.ripper.ast_engine import ASTRipper

logger = Config.setup_logger("BugBot.Ripper", "bugbot_ripper.log")

class RipperOrchestrator:
    """Orquestador atómico para el destripado de Frontend."""
    
    def __init__(self, target_domain: str, concurrency: int = 3):
        self.target_domain = target_domain
        self.semaphore = asyncio.Semaphore(concurrency)
        self.downloader = JSDownloader()
        self.ast_engine = ASTRipper(self.semaphore)

    async def run(self, js_urls: List[str]) -> List[str]:
        if not js_urls: return []
        
        logger.info(f"[*] Ripper: Mapeando {len(js_urls)} archivos JS...")
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._process_js(session, url) for url in js_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            flat_endpoints = set()
            for r in results:
                if isinstance(r, Exception):
                    continue
                for endpoint in r:
                    if endpoint.strip():
                        flat_endpoints.add(endpoint.strip())
            
            return sorted(list(flat_endpoints))

    async def _process_js(self, session, url: str) -> List[str]:
        content = await self.downloader.download_to_ram(session, url)
        if content:
            return await self.ast_engine.rip(content)
        return []
