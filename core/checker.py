import asyncio
import aiohttp
import random
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.config import Config
from core.memory_cortex import MemoryCortex

# Reuso de configuración de logging
logger = logging.getLogger("BugBot.Checker")

class Checker:
    """
    Motor de Verificación Senior:
    - Concurrencia Controlada (Semáforo de 50)
    - Reintentos Inteligentes
    - Stealth Headers
    - Resiliencia ante fallos
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    ]

    def __init__(self, concurrency: int = 50, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency) # Regla 2
        self.timeout = aiohttp.ClientTimeout(total=timeout) # Regla 1
        self.max_retries = 3
        self.brain = MemoryCortex()

    def _get_random_ua(self) -> str:
        return random.choice(self.USER_AGENTS)

    async def check_url(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Verifica un solo host con lógica de reintentos y semáforo."""
        domain = urlparse(url).netloc
        if self.brain.is_dead_endpoint(domain):
            logger.debug(f"[*] Brain Skip: Ignorando Dead Endpoint conocido -> {domain}")
            return None
            
        async with self.semaphore:
            for attempt in range(self.max_retries):
                try:
                    headers = {"User-Agent": self._get_random_ua()}
                    headers.update(Config.CUSTOM_HEADERS) # Identificación legal inyectada
                    async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True) as response:
                        # Regla 1: Manejo de 429 y 500+ con wait exponencial
                        if response.status == 429 or response.status >= 500:
                            wait = (2 ** attempt) + random.random()
                            await asyncio.sleep(wait)
                            continue

                        # Regla 4: Datos estandarizados
                        return {
                            "url": str(response.url),
                            "status": response.status,
                            "server": response.headers.get("Server", "Unknown"),
                            "content_type": response.headers.get("Content-Type", "Unknown").split(';')[0]
                        }
                except Exception as e:
                    # Regla 3: Silencioso y resiliente
                    if attempt == self.max_retries - 1:
                        logger.debug(f"[-] Fallo definitivo en {url}: {e}")
                        self.brain.memorize_dead_endpoint(domain, reason=f"Connection Error: {e}")
                    await asyncio.sleep(0.5)
            return None

    async def run(self, subdomains: List[str]) -> List[Dict]:
        """Orquestador asíncrono para validar la lista de subdominios."""
        logger.info(f"[*] Verificando {len(subdomains)} potenciales hosts...")
        
        results = []
        import sys
        connector = None
        if sys.platform == 'win32':
            resolver = aiohttp.ThreadedResolver()
            connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
            
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for sub in subdomains:
                # Probamos tanto http como https (Regla de oro del Bug Bounty)
                tasks.append(self.check_url(session, f"https://{sub}"))
                tasks.append(self.check_url(session, f"http://{sub}"))
            
            # Ejecución concurrente segura
            responses = await asyncio.gather(*tasks)
            results = [r for r in responses if r]
            
        logger.info(f"[+] Verificación completada. {len(results)} hosts vivos detectados.")
        return results
