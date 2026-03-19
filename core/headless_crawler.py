import asyncio
import logging
import os
import tldextract
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from core.config import Config

logger = Config.setup_logger("BugBot.HeadlessCrawler", "bugbot_headless_crawler.log")

class HeadlessCrawler:
    """
    Crawler de Inteligencia Elite (v2.0):
    - Usa Playwright (Chromium Headless).
    - Captura llamadas XHR/Fetch (APIs ocultas).
    - Extrae JS dinámicos generados por React/Next.js.
    """

    BLACKLISTED_CDNS = [
        "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net", 
        "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
        "yastatic.net", "polyfill.io", "cdn.cloudflare.com", "fonts.googleapis.com",
        "wix.com", "parastorage.com", "sentry-cdn.com", "stripe.com", "google-analytics.com",
        "googletagmanager.com", "facebook.net"
    ]

    # Subdominios que nunca responderán por HTTP (servicios de infraestructura)
    SKIP_SUBDOMAINS = [
        "autodiscover", "mail", "smtp", "pop", "imap", "ftp",
        "ns1", "ns2", "ns3", "ns4", "dns", "ntp",
        "vpn", "rdp", "ssh", "sip", "lyncdiscover",
    ]

    def __init__(self, concurrency: int = 5, timeout: int = 30):
        # Playwright es pesado en memoria, limitamos a 5 pestañas concurrentes por seguridad
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout * 1000  # transformamos a milisegundos
        self.results = {}

    def should_crawl_link(self, link_url: str, target_domain: str) -> bool:
        """
        Filtro estricto de Same-Origin (Mismo Origen).
        El crawler jamás debe abandonar la marca del objetivo principal.
        """
        extracted_link = tldextract.extract(link_url)
        extracted_target = tldextract.extract(target_domain)
        
        # Solo permite rastrear si el dominio raíz coincide (ej. playticorp == playticorp)
        if extracted_link.domain == extracted_target.domain:
            return True
        return False

    async def crawl_url(self, browser, base_url: str) -> Dict:
        """Navega a una URL y captura tráfico de fondo JS/XHR."""
        empty_result = (base_url, {'links_internos': [], 'archivos_js': [], 'api_endpoints': []})

        # Pre-filtro: Saltar subdominios de infraestructura que nunca sirven HTTP
        parsed_check = urlparse(base_url)
        hostname = parsed_check.hostname or ""
        subdomain = hostname.split('.')[0] if hostname else ""
        if subdomain.lower() in self.SKIP_SUBDOMAINS:
            logger.info(f"[SKIP] {base_url} (subdominio no-web: {subdomain})")
            return empty_result

        data = {
            'links_internos': set(),
            'archivos_js': set(),
            'api_endpoints': [], # Cambiado a lista para guardar diccionarios complejos
            'api_urls_vistas': set() # Set auxiliar para avoid duplicados
        }

        async with self.semaphore:
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=Config.CUSTOM_HEADERS,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            # 1. Enrutamiento Activo (Bloquear descargas inútiles y capturar APIs)
            async def handle_route(route):
                try:
                    request = route.request
                    url = request.url
                    resource_type = request.resource_type
                    
                    # Bloquear basura para ganar velocidad (Filtro Activo)
                    if resource_type in ['image', 'media', 'font', 'stylesheet', 'websocket']:
                        await route.abort()
                        return
                    
                    # 2. Capturar Archivos JS (SourceMaps Phase)
                    if resource_type == 'script' or url.endswith('.js'):
                        if not any(cdn in url.lower() for cdn in self.BLACKLISTED_CDNS):
                            data['archivos_js'].add(url)
                    
                    # 3. Capturar ENDPOINTS API OCULTOS (El "Oro" de SPAs)
                    elif resource_type in ['fetch', 'xhr']:
                        if not any(cdn in url.lower() for cdn in self.BLACKLISTED_CDNS):
                            if self.should_crawl_link(url, base_url) or "api" in url.lower():
                                if url not in data['api_urls_vistas']:
                                    data['api_urls_vistas'].add(url)
                                    data['api_endpoints'].append({
                                        'url': url,
                                        'method': request.method,
                                        'headers': request.headers
                                    })
                            
                    # 4. Capturar Links de Navegación
                    elif resource_type == 'document':
                        if self.should_crawl_link(url, base_url):
                            data['links_internos'].add(url.split('#')[0])

                    await route.continue_()
                except Exception:
                    # Si la página se cerró o la ruta ya fue manejada, ignorar
                    pass

            await page.route("**/*", handle_route)

            print(f"[+] Headless Spider: Infiltrándose en {base_url} ...")
            try:
                # Estrategia resiliente: domcontentloaded (rápido) + networkidle como bonus
                await page.goto(base_url, timeout=self.timeout, wait_until="domcontentloaded")
                # Intentar networkidle como bonus (10s), no es bloqueante si falla
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except PlaywrightTimeoutError:
                    pass  # OK: DOM ya cargado, networkidle es un bonus
                await page.wait_for_timeout(2000) # Tiempo para hidratación de React/Angular
            except PlaywrightTimeoutError:
                logger.warning(f"[-] Tiempo excedido en {base_url} (DOM cargado, extrayendo datos igualmente).")
            except Exception as e:
                logger.error(f"[-] Fallo en {base_url}: {e}")
                await context.close()
                return empty_result

            # Garantizar la Extracción de Enlaces incluso si falló el networkidle
            try:
                # Raspar enlaces <a> procesados y dibujados en el DOM por JS (Dynamic Links)
                hrefs = await page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('a')).map(a => a.href);
                }''')
                
                for href in hrefs:
                    if href:
                        if self.should_crawl_link(href, base_url):
                            data['links_internos'].add(href.split('#')[0])
            except Exception as e:
                logger.debug(f"[-] Error extrayendo hrefs en {base_url}: {e}")
            finally:
                await context.close()
                api_x = len(data['api_endpoints'])
                js_x = len(data['archivos_js'])
                print(f"    -> [Interceptados] {api_x} APIs (XHR) | {js_x} Scripts JS")

        return base_url, {
            'links_internos': sorted(list(data['links_internos'])),
            'archivos_js': sorted(list(data['archivos_js'])),
            'api_endpoints': data['api_endpoints']
        }

    async def run(self, urls: List[str], max_depth: int = 1) -> Dict[str, Dict]:
        """Orquesta el Headless Browsing con concurrencia controlada."""
        if not urls: return {}
            
        logger.info(f"[*] Iniciando Spider Headless en {len(urls)} URLs")
        results = {}
        visited = set()
        to_visit = set(urls)

        async with async_playwright() as p:
            # Usar Chromium
            print("[*] Levantando Motor Chromium de Alto Rendimiento...")
            browser = await p.chromium.launch(
                headless=True, 
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-http2']
            )

            for current_depth in range(max_depth):
                if not to_visit: break
                
                print(f"[*] Crawler: Procesando profundidad {current_depth + 1}/{max_depth} (Targets: {len(to_visit)})")
                tasks = [self.crawl_url(browser, url) for url in to_visit if url not in visited]
                visited.update(to_visit)
                
                if tasks:
                    batch_responses = await asyncio.gather(*tasks, return_exceptions=True)
                    to_visit = set()
                    for result in batch_responses:
                        if isinstance(result, Exception):
                            logger.error(f"[-] Error en batch de crawling: {result}")
                            continue
                        url, data = result
                        if url:
                            results[url] = data
                            if current_depth < max_depth - 1:
                                for link in data['links_internos']:
                                    if link not in visited:
                                        to_visit.add(link)
                else: break

            await browser.close()

        self.results = results
        return results
