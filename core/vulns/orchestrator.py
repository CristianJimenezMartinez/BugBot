import asyncio
import aiohttp
import logging
from typing import List, Dict
from core.config import Config
from core.oob_engine import OOBEngine
from core.memory_cortex import MemoryCortex

from core.vulns.ssrf import SSRFScanner
from core.vulns.idor import IDORScanner
from core.vulns.lfi import LFIScanner
from core.vulns.xss import XSSScanner
from core.vulns.redirect import RedirectScanner
from core.vulns.hidden_params import HiddenParamsScanner

logger = Config.setup_logger("BugBot.Vuln", "bugbot_vuln.log")

class VulnOrchestrator:
    """Orquestador atómico para la pipeline de vulnerabilidades."""
    
    def __init__(self, concurrency: int = 20, timeout: int = 15):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.oob = OOBEngine()
        self.cortex = MemoryCortex()

    async def run_discovery(self, urls: List[str]) -> List[Dict]:
        """Ejecuta todos los scans atómicos de forma concurrente."""
        if not urls: return []
            
        all_findings = []
        connector = Config.get_connector()
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Inicializamos los escáneres atómicos
            scanners = {
                "ssrf": SSRFScanner(session, self.semaphore, self.timeout),
                "idor": IDORScanner(session, self.semaphore, self.timeout),
                "lfi": LFIScanner(session, self.semaphore, self.timeout),
                "xss": XSSScanner(session, self.semaphore, self.timeout),
                "redirect": RedirectScanner(session, self.semaphore, self.timeout),
                "hidden": HiddenParamsScanner(session, self.semaphore, self.timeout)
            }
            
            tasks = []
            for url in list(set(urls)):
                # Lanzamos cheques atómicos por cada URL
                tasks.append(scanners["ssrf"].check(url, self.oob))
                tasks.append(scanners["idor"].check(url))
                tasks.append(scanners["lfi"].check(url))
                tasks.append(scanners["xss"].check(url))
                tasks.append(scanners["redirect"].check(url))
                tasks.append(scanners["hidden"].check(url))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict):
                    all_findings.append(res)
                elif isinstance(res, Exception):
                    logger.debug(f"[!] Error en tarea Vuln: {res}")
                    
        return all_findings
