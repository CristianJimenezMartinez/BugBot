import asyncio
import logging
from typing import List, Dict
from core.config import Config
from core.fuzzer.constants import get_random_ua, CRITICAL_API_ENDPOINTS

logger = logging.getLogger("BugBot.Fuzzer.Sniper")

class APISniper:
    """Motor especializado en endpoints críticos de infraestructura."""
    
    def __init__(self, semaphore: asyncio.Semaphore, timeout: int = 10):
        self.semaphore = semaphore
        self.timeout = timeout

    async def run(self, session, base_url: str) -> List[Dict]:
        """Universal API Sniper (v2.1)"""
        findings = []
        MILITARY_GRADE_KEYWORDS = ["secrets", "script", "credentials", "config", "debug", "env", "sql"]
        
        for path in CRITICAL_API_ENDPOINTS:
            url = base_url.rstrip("/") + path
            await asyncio.sleep(0.05)
            
            async with self.semaphore:
                try:
                    headers = {"User-Agent": get_random_ua(), "Accept": "application/json"}
                    headers.update(Config.CUSTOM_HEADERS)
                    async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                        content_type = response.headers.get("Content-Type", "").lower()
                        if "json" not in content_type:
                            continue

                        if response.status == 200:
                            content = await response.text(errors='ignore')
                            if "{" in content and "}" in content:
                                severity = "HIGH"
                                details = "API Expuesta detectada."
                                
                                if any(kw in path.lower() for kw in MILITARY_GRADE_KEYWORDS):
                                    severity = "CRITICAL (MILITARY GRADE)"
                                    details = "⚠️ ALERTA: Consola Administrativa o Secrets expuestos."
                                    logger.error(f"[🚨] HALLAZGO CRÍTICO EN {url}.")

                                findings.append({
                                    "url": url,
                                    "status": 200,
                                    "size": len(content),
                                    "path": path,
                                    "impacto": severity,
                                    "detalles": details,
                                    "juicy_extracted": ["Raw API JSON Dump detected without authentication."],
                                    "waf_bypass": None,
                                    "severity": severity,
                                    "finding_type": "VULN"
                                })
                except Exception:
                    pass
        return findings
