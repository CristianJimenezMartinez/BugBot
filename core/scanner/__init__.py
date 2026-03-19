import asyncio
from typing import List, Dict
from core.scanner.orchestrator import ScannerOrchestrator

class Scanner:
    """
    Facade Atómico para BugBot Scanner.
    Delega toda la lógica de detección de secretos a ScannerOrchestrator.
    """
    def __init__(self, concurrency: int = 15, timeout: int = 10):
        self._orchestrator = ScannerOrchestrator(concurrency=concurrency, timeout=timeout)
        self.findings = []

    async def run(self, js_urls: List[str]) -> List[Dict]:
        self.findings = await self._orchestrator.run(js_urls)
        return self.findings
