import asyncio
import aiohttp
import random
import logging
import os
from typing import List, Dict, Set
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from core.config import Config

# Configuración de Logging
logger = Config.setup_logger("BugBot.Crawler", "bugbot_crawler.log")

class Crawler:
    """
    [DEPRECATED] Crawler de Inteligencia Senior (v1.1).
    Este módulo NO se usa en producción — usar HeadlessCrawler (headless_crawler.py).
    Se mantiene como referencia de la implementación basada en aiohttp/BeautifulSoup.
    
    - Profundidad 1 (Solo página principal).
    - Concurrencia Controlada (Estabilidad Windows Iron).
    - Evasión de WAF (Chrome v121 User-Agent).
    - Resiliencia Total (Manejo de errores silencioso).
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    ]

    # CDNs públicos y librerías externas que NO nos interesan (Falsos Positivos)
    BLACKLISTED_CDNS = [
        "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net", 
        "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
        "yastatic.net", "polyfill.io", "cdn.cloudflare.com", "fonts.googleapis.com",
        "wix.com", "parastorage.com", "sentry-cdn.com", "github.io", "github.com"
    ]

    def __init__(self, concurrency: int = 20, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency) 
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.results = {}

    def _get_random_ua(self) -> str:
        return random.choice(self.USER_AGENTS)

    def should_crawl_link(self, link_url: str, target_domain: str) -> bool:
        """
        Filtro estricto de Same-Origin (Mismo Origen).
        El crawler jamás debe abandonar la marca del objetivo principal.
        """
        import tldextract
        extracted_link = tldextract.extract(link_url)
        extracted_target = tldextract.extract(target_domain)
        
        # Solo permite rastrear si el dominio raíz coincide (ej. playticorp == playticorp)
        if extracted_link.domain == extracted_target.domain:
            return True
        return False

    async def crawl_url(self, session: aiohttp.ClientSession, base_url: str) -> Dict:
        """Extrae links internos y archivos JS de una URL única."""
        data = {
            'links_internos': set(),
            'archivos_js': set()
        }

        async with self.semaphore:
            try:
                headers = {"User-Agent": self._get_random_ua()}
                headers.update(Config.CUSTOM_HEADERS) # Inyección obligatoria de cabeceras de identificación
                
                async with session.get(base_url, headers=headers, timeout=self.timeout, allow_redirects=True) as response:
                    print(f"[+] Crawler: {base_url} devolvió HTTP {response.status}")
                    
                    if response.status == 200:
                        # [Resilience] Manejo robusto de codificación
                        raw_bytes = await response.read()
                        try:
                            html = raw_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            html = raw_bytes.decode('latin-1', errors='replace')
                            
                        soup = BeautifulSoup(html, 'html.parser')
                        parsed_base = urlparse(base_url)

                        # 1. Extracción de enlaces internos (Control estricto de dominio)
                        for a in soup.find_all('a', href=True):
                            link = urljoin(base_url, a['href'])
                            parsed_link = urlparse(link)
                            
                            # Regla Senior (Domain Lock): Validar la raíz del dominio mediante tldextract
                            if self.should_crawl_link(link, base_url):
                                data['links_internos'].add(link.split('#')[0])

                        # 2. Extracción de archivos JavaScript (Resolución absoluta obligatoria)
                        for script in soup.find_all('script', src=True):
                            js_link = urljoin(base_url, script['src'])
                            # Filtro Anti-Falsos Positivos: No guardar JS de CDNs públicos
                            if not any(cdn in js_link.lower() for cdn in self.BLACKLISTED_CDNS):
                                data['archivos_js'].add(js_link)
                    else:
                        print(f"[-] Crawler: Error en {base_url} (Status: {response.status})")

            except Exception as e:
                # Regla de Resiliencia: Informar y continuar
                print(f"[!] Crawler: Error crítico en {base_url} -> {e}")
                logger.error(f"[-] Fallo en crawling de {base_url}: {e}")
        
        # Convertir sets a listas para serialización JSON (Regla de Estandarización)
        return base_url, {
            'links_internos': sorted(list(data['links_internos'])),
            'archivos_js': sorted(list(data['archivos_js']))
        }

    async def run(self, urls: List[str], max_depth: int = 1) -> Dict[str, Dict]:
        """Orquesta el rastreo de múltiples URLs con soporte de profundidad."""
        if not urls:
            return {}

        # Parche crítico para Windows aiodns compatibility
        import sys

        logger.info(f"[*] Iniciando crawling en {len(urls)} URLs (Profundidad: {max_depth})")
        
        # Forzar el uso de un resolver que no dependa de aiodns (Evita RuntimeError en Windows)
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=True)
        
        results = {}
        visited = set()
        to_visit = set(urls)

        async with aiohttp.ClientSession(connector=connector) as session:
            for current_depth in range(max_depth):
                if not to_visit: break
                
                print(f"[*] Crawler: Procesando nivel de profundidad {current_depth + 1}/{max_depth} (Objetivos: {len(to_visit)})")
                
                # Crear tareas para el nivel actual
                tasks = [self.crawl_url(session, url) for url in to_visit if url not in visited]
                visited.update(to_visit)
                
                if tasks:
                    batch_responses = await asyncio.gather(*tasks)
                    to_visit = set() # Limpiar para el siguiente nivel
                    for url, data in batch_responses:
                        if url:
                            results[url] = data
                            # Añadir nuevos links internos para el siguiente nivel
                            if current_depth < max_depth - 1:
                                for link in data['links_internos']:
                                    if link not in visited:
                                        to_visit.add(link)
                else:
                    break

        self.results = results
        return results

if __name__ == '__main__':
    # Configuración de compatibilidad para Windows
    import sys

    # Dryden Run: Tesla de prueba (VulnWeb)
    async def dry_run():
        test_url = "http://testphp.vulnweb.com"
        print(f"\n[!] INICIANDO DRY RUN (Senior Crawler v1.0)")
        print(f"[*] Objetivo: {test_url}")
        
        crawler = Crawler()
        results = await crawler.run([test_url])
        
        intel = results.get(test_url, {})
        
        print("\n" + "="*40)
        print(f"HALLAZGOS EN: {test_url}")
        print(f"Links Internos encontrados: {len(intel.get('links_internos', []))}")
        print(f"Archivos JS encontrados:    {len(intel.get('archivos_js', []))}")
        print("="*40)
        
        if intel.get('archivos_js'):
            print("\nÚltimos 3 archivos JS descubiertos:")
            for js in intel['archivos_js'][-3:]:
                print(f" -> {js}")
        print("="*40 + "\n")

    asyncio.run(dry_run())
