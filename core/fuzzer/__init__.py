import asyncio
from typing import List, Dict
from core.fuzzer.orchestrator import FuzzerOrchestrator

class Fuzzer:
    """
    Facade Atómico para BugBot Fuzzer (vía __init__).
    Delega toda la lógica a FuzzerOrchestrator.
    """
    def __init__(self, concurrency: int = 30, timeout: int = 10):
        self._orchestrator = FuzzerOrchestrator(concurrency=concurrency, timeout=timeout)
        self.findings = []

    async def run(self, live_urls: List[str]) -> List[Dict]:
        self.findings = await self._orchestrator.run(live_urls)
        return self.findings
