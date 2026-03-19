import logging
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, urlunparse
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.Redirect")

class RedirectScanner(VulnScannerBase):
    """Motor atómico para detección de Open Redirect."""
    
    async def check(self, url: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return None
        
        payload = "https://google.com"
        
        for param in params:
            original = params[param][0]
            if any(kw in param.lower() for kw in ["url", "redirect", "next", "goto", "out"]):
                params[param] = [payload]
                new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
                test_url = urlunparse(parsed._replace(query=new_query))
                
                res = await self._safe_get(test_url)
                if res and (res["status"] in [301, 302] and "google.com" in res["headers"].get("Location", "")):
                    return {
                        "url": test_url,
                        "tipo": "OPEN_REDIRECT",
                        "impacto": "LOW",
                        "detalles": f"Redirección abierta en '{param}' hacia {payload}"
                    }
                params[param] = [original]
        return None
