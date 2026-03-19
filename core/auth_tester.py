import asyncio
from typing import List, Dict
from core.auth.orchestrator import AuthOrchestrator

class AuthTester:
    """
    Facade Atómico para BugBot AuthTester.
    Delega las pruebas de IDOR/BOLA a AuthOrchestrator.
    """
    def __init__(self, token_user_A: dict, token_user_B: dict = None, concurrency: int = 5, timeout: int = 15):
        self._orchestrator = AuthOrchestrator(token_user_A, token_user_B, concurrency)
        self.findings = []

    async def run(self, intercepted_requests: List[dict]) -> List[Dict]:
        self.findings = await self._orchestrator.run(intercepted_requests)
        return self.findings
