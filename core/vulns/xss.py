import logging
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, urlunparse
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.XSS")

class XSSScanner(VulnScannerBase):
    """Motor atómico para detección de XSS Reflejado."""
    
    async def check(self, url: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return None
        
        payload = "<script>alert(1)</script>"
        
        for param in params:
            original = params[param][0]
            params[param] = [payload]
            new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
            test_url = urlunparse(parsed._replace(query=new_query))
            
            res = await self._safe_get(test_url)
            if res and payload in res["content"]:
                # Importante en Bug Bounty: Muchos son falsos positivos por falta de context escape
                return {
                    "url": test_url,
                    "tipo": "XSS_REFLECTED",
                    "impacto": "MEDIUM",
                    "detalles": f"Payload XSS reflejado en cuerpo de respuesta: {param}"
                }
            params[param] = [original]
        return None
