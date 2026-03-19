import logging
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs
from core.vulns.base import VulnScannerBase

logger = logging.getLogger("BugBot.Vulns.IDOR")

class IDORScanner(VulnScannerBase):
    """Motor atómico para detección de IDOR/BOLA."""
    
    async def check(self, url: str) -> Optional[Dict]:
        """Escaneo pasivo de parámetros candidatos a IDOR."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        idor_keywords = ["id", "user", "account", "order", "invoice", "doc", "uuid", "key", "uid"]
        
        for param in params:
            if any(kw in param.lower() for kw in idor_keywords):
                return {
                    "url": url,
                    "tipo": "IDOR_CANDIDATE",
                    "impacto": "MEDIUM",
                    "detalles": f"Parámetro ID detectado: {param}. Requiere test de autorización activo."
                }
        return None
