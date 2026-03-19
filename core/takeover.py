import aiohttp
import asyncio
import logging
from typing import Optional, Dict
from core.config import Config

logger = logging.getLogger("BugBot.TakeoverScanner")

class TakeoverScanner:
    """
    Escáner Quirúrgico de Subdomain Takeovers (Dangling DNS).
    Identifica si un subdominio apunta a un servicio Cloud (AWS, GitHub, Heroku, etc.)
    que ha sido abandonado, permitiendo registrarlo y secuestrar el subdominio.
    """
    
    # Firmas conocidas de servicios Cloud abandonados (Cero Falsos Positivos)
    SIGNATURES = {
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
        "Heroku": ["No such app", "Heroku | No such app"],
        "Azure": ["404 Web Site not found", "appservice.windows.net"],
        "Shopify": ["Sorry, this shop is currently unavailable."],
        "Fastly": ["Fastly error: unknown domain"],
        "Ghost": ["The thing you were looking for is no longer here, or never was"],
        "Pantheon": ["The sitename you are looking for could not be found."],
        "Tumblr": ["Whatever you were looking for doesn't currently exist at this address."],
        "WordPress": ["Do you want to register"],
        "Zendesk": ["Help Center Closed"],
        "WP Engine": ["The site you were looking for couldn't be found."],
        "Bitbucket": ["Repository not found"],
        "Squarespace": ["Squarespace - Claim This Domain"],
        "Fly.io": ["404 Not Found"]
    }

    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _verify_cname_heuristic(self, domain: str, service: str) -> bool:
        """Verificación DNS Experta (Anti Falsos Positivos CDN/WAF)."""
        import dns.resolver
        import socket
        
        blacklisted_cdns = ["akamai", "cloudflare", "fastly", "incapsula", "cloudfront"]
        
        try:
            # 1. Intentar resolver CNAME explícito (Captura el Dangling DNS aunque no haya IP)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, 'CNAME')
                for rdata in answers:
                    target = str(rdata.target).lower()
                    
                    # Filtro Crítico Anti-CDN: Si apunta a una CDN, morir aquí.
                    if any(cdn in target for cdn in blacklisted_cdns):
                        logger.warning(f"[!] Falso Positivo DNS (CDN detectada en CNAME): {domain} -> {target}")
                        return False
                    
                    # Si el CNAME apunta al servicio que disparó la firma HTTP (ej. s3.amazonaws.com)
                    service_keywords = {
                        "AWS S3": "amazonaws", "GitHub Pages": "github", "Heroku": "herokudns",
                        "Azure": "windows.net", "Shopify": "myshopify", "Fastly": "fastly",
                        "Ghost": "ghost.io", "Pantheon": "pantheonsite", "Tumblr": "tumblr.com",
                        "WordPress": "wordpress.com", "Zendesk": "zendesk.com", "WP Engine": "wpengine",
                        "Bitbucket": "bitbucket.io", "Squarespace": "squarespace.com", "Fly.io": "fly.dev"
                    }
                    
                    keyword = service_keywords.get(service, service.lower().split()[0])
                    if keyword in target:
                        return True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # No hay CNAME explícito, probamos si resuelve a IP
                try:
                    await asyncio.to_thread(socket.gethostbyname, domain)
                    # Si resuelve a IP pero no vimos CNAME, el riesgo de Takeover es bajísimo/nulo
                    return False 
                except socket.gaierror:
                    # No resuelve a nada. Si hubo firma HTTP, es muy sospechoso (Dangling)
                    return True

            return False
        except Exception as e:
            logger.debug(f"[Takeover DNS Error] {e}")
            return False

    async def scan(self, target_url: str) -> Optional[Dict]:
        """Realiza una petición a la raíz, comprueba firmas HTTP y valida el DNS CNAME."""
        from urllib.parse import urlparse
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.hostname
        
        urls_to_test = [target_url]
        if target_url.startswith("https://"):
            urls_to_test.append(target_url.replace("https://", "http://"))
            
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector, headers=Config.CUSTOM_HEADERS) as session:
            for url in urls_to_test:
                try:
                    # No permitimos redirecciones para evitar que nos lleve al dominio principal sano
                    async with session.get(url, timeout=self.timeout, allow_redirects=False) as response:
                        content = await response.text(errors='ignore')
                        
                        for service, sigs in self.SIGNATURES.items():
                            for sig in sigs:
                                if sig in content:
                                    # Posible Takeover por HTTP... ¡Momento del doble check experto DNS!
                                    is_vulnerable = await self._verify_cname_heuristic(domain, service)
                                    
                                    if is_vulnerable:
                                        return {
                                            "tipo": "SUBDOMAIN_TAKEOVER",
                                            "url": url,
                                            "impacto": "CRITICAL (Account Takeover / Phishing a gran escala)",
                                            "detalles": f"El servicio {service} parece estar abandonado. Firma detectada: '{sig}' y DNS Validado."
                                        }
                                    else:
                                        logger.warning(f"[!] Falso Positivo Takeover Bloqueado por DNS (Akamai/CDN): {url}")
                                        return None # Abortamos, era un Espejismo de CDN
                except Exception as e:
                    pass
                    
        return None
