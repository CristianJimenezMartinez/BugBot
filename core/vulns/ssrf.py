import logging
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs, urlunparse
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.SSRF")

class SSRFScanner(VulnScannerBase):
    """Motor atómico para detección de SSRF."""
    
    async def check(self, url: str, oob_engine) -> Optional[Dict]:
        """Prueba SSRF inyectando el OOB Engine."""
        if not oob_engine: return None
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return None
        
        found = False
        oob_payload = oob_engine.get_callback_url()
        
        for param in params:
            original_val = params[param][0]
            if any(kw in original_val.lower() for kw in ["http", "ssh", "file", "path", "url"]):
                params[param] = [oob_payload]
                new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
                test_url = urlunparse(parsed._replace(query=new_query))
                
                res = await self._safe_get(test_url)
                if res and res["status"] in [200, 301, 302]:
                    # La confirmación real viene del polling de OOB
                    found = True
                params[param] = [original_val]
        
        if found:
            return {
                "url": url,
                "tipo": "SSRF_POTENTIAL",
                "impacto": "HIGH",
                "detalles": f"Parámetro sospechoso inyectado con OOB: {oob_payload}"
            }
        return None
