import asyncio
import socket
import logging
from typing import List, Dict
from core.config import Config
from core.cloud.mutator import CloudMutator
from core.cloud.engine import CloudEngine
from core.cloud.constants import GENERIC_IGNORE_LIST

logger = Config.setup_logger("BugBot.Cloud", "bugbot_cloud.log")

class CloudOrchestrator:
    """Orquestador atómico para la caza de buckets."""
    
    def __init__(self, concurrency: int = 50, strict_mode: bool = True):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.engine = CloudEngine(self.semaphore, strict_mode=strict_mode)
        self.mutator = CloudMutator()
        self.cname_mappings = {} # bucket_url -> cname

    async def run(self, base_domain: str, known_subdomains: List[str] = None) -> List[Dict]:
        if base_domain.split('.')[0] in GENERIC_IGNORE_LIST: return []
        
        logger.info(f"[*] Iniciando CloudOrchestrator: {base_domain}")
        
        # 1. Resolución de CNAMEs para identificar targets legítimos
        if known_subdomains:
            async def resolve(sub):
                try:
                    # Usamos thread para evitar bloqueo DNS síncrono
                    _, aliases, _ = await asyncio.to_thread(socket.gethostbyname_ex, sub)
                    for alias in aliases:
                        if any(c in alias for c in ["amazonaws.com", "windows.net", "googleapis.com"]):
                            url = f"https://{alias}"
                            self.cname_mappings[url] = sub
                except Exception: pass
            
            await asyncio.gather(*[resolve(s) for s in known_subdomains], return_exceptions=True)

        # 2. Generación de URLs por mutación
        names = self.mutator.generate_names(base_domain)
        all_urls = set()
        for name in names:
            for url in self.mutator.generate_urls(name):
                all_urls.add(url)
        
        # Añadirlos CNAMEs resueltos
        for url in self.cname_mappings.keys():
            all_urls.add(url)

        # 3. Auditoría Concurrente
        import aiohttp
        async with aiohttp.ClientSession(connector=Config.get_connector()) as session:
            tasks = []
            for url in all_urls:
                tasks.append(self.engine.audit_url(session, url, self.cname_mappings.get(url)))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if r and not isinstance(r, Exception)]
