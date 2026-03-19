import asyncio
import aiohttp
import logging
from typing import List, Dict
from urllib.parse import urlparse

from core.config import Config
from core.wordlists import WordlistManager
from core.memory_cortex import MemoryCortex
from core.fuzzer.constants import SENSITIVE_FILES
from core.fuzzer.network import NetworkHunter
from core.fuzzer.calibrator import FuzzerCalibrator
from core.fuzzer.sniper import APISniper
from core.fuzzer.engine import FuzzerEngine

logger = Config.setup_logger("BugBot.Fuzzer", "bugbot_fuzzer.log")

class FuzzerOrchestrator:
    """Orquestador atómico que cumple la interfaz original de BugBot."""
    
    def __init__(self, concurrency: int = 30, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.cortex = MemoryCortex()
        self.wordlists = WordlistManager()
        self.network = NetworkHunter()
        self.calibrator = FuzzerCalibrator(timeout=timeout)
        self.sniper = APISniper(semaphore=self.semaphore, timeout=timeout)
        self.engine = FuzzerEngine(semaphore=self.semaphore, cortex=self.cortex, timeout=timeout)
        self.findings = []

    async def run(self, live_urls: List[str]) -> List[Dict]:
        """Método principal compatible con el pipeline."""
        if not live_urls: return []
            
        alive_hosts = []
        for u in live_urls:
            domain = urlparse(u).netloc
            if self.cortex.is_currently_banned(domain):
                logger.warning(f"[🧠] Cooldown activo en {domain}.")
                continue
            if await self.network.check_host(u): alive_hosts.append(u)
                
        if not alive_hosts: return []

        dynamic_list = self.wordlists.get_wordlist("common_config") + self.wordlists.get_wordlist("backups_logs")
        fuzz_list = (dynamic_list if dynamic_list else SENSITIVE_FILES)[:500]

        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            baselines = {}
            for url in alive_hosts:
                baselines[url] = await self.calibrator.calibrate_host(session, url)
                await asyncio.sleep(0.3)
                
            results = []
            all_paths_data = [(u, p) for u in alive_hosts for p in fuzz_list]
            chunk_size = 50

            for i in range(0, len(all_paths_data), chunk_size):
                batch = all_paths_data[i:i + chunk_size]
                batch_tasks = [self.engine.fuzz_path(session, u, p, baselines[u]) for u, p in batch]
                batch_res = await asyncio.gather(*batch_tasks, return_exceptions=True)
                results.extend([r for r in batch_res if not isinstance(r, Exception)])
                await asyncio.sleep(0.5)

            for url in alive_hosts:
                sniper_res = await self.sniper.run(session, url)
                if sniper_res: results.extend(sniper_res)
                    
            self.findings = [r for r in results if isinstance(r, dict)]
        
        return self.findings
