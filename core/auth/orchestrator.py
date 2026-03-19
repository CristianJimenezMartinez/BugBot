import asyncio
import aiohttp
import logging
from typing import List, Dict
from core.config import Config
from core.auth.engine import AuthEngine

logger = Config.setup_logger("BugBot.Auth", "bugbot_auth.log")

class AuthOrchestrator:
    """Orquestador atómico para pruebas de autorización."""
    
    def __init__(self, session_A: dict, session_B: dict = None, concurrency: int = 5):
        self.engine = AuthEngine(session_A, session_B)
        self.semaphore = asyncio.Semaphore(concurrency)

    async def run(self, intercepted_requests: List[dict]) -> List[Dict]:
        if not intercepted_requests: return []
        
        logger.info(f"[*] Iniciando Cacería IDOR en {len(intercepted_requests)} rutas...")
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for req in intercepted_requests:
                tasks.append(self._guarded_test(session, req))
            
            results = await asyncio.gather(*tasks)
            return [r for r in results if r]

    async def _guarded_test(self, session, req: dict):
        async with self.semaphore:
            # Jitter
            import random
            await asyncio.sleep(random.uniform(0.5, 1.2))
            return await self.engine.test_idor(session, req)
